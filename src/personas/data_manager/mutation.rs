// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::data::{Data, DataId};
use log::LogLevel;
use maidsafe_utilities::serialisation::serialised_size;
use routing::{EntryAction, ImmutableData, MutableData, PermissionSet, User, XorName};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
pub enum Mutation {
    PutIData(ImmutableData),
    PutMData(MutableData),
    MutateMDataEntries {
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
    },
    SetMDataUserPermissions {
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
    },
    DelMDataUserPermissions {
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
    },
    ChangeMDataOwner {
        name: XorName,
        tag: u64,
        new_owners: BTreeSet<sign::PublicKey>,
        version: u64,
    },
}

impl Mutation {
    pub fn data_id(&self) -> DataId {
        match *self {
            Mutation::PutIData(ref data) => DataId::Immutable(data.id()),
            Mutation::PutMData(ref data) => DataId::Mutable(data.id()),
            Mutation::MutateMDataEntries { name, tag, .. } |
            Mutation::SetMDataUserPermissions { name, tag, .. } |
            Mutation::DelMDataUserPermissions { name, tag, .. } |
            Mutation::ChangeMDataOwner { name, tag, .. } => DataId::mutable(name, tag),
        }
    }

    pub fn mutation_type(&self) -> MutationType {
        match *self {
            Mutation::PutIData(_) => MutationType::PutIData,
            Mutation::PutMData(_) => MutationType::PutMData,
            Mutation::MutateMDataEntries { .. } => MutationType::MutateMDataEntries,
            Mutation::SetMDataUserPermissions { .. } => MutationType::SetMDataUserPermissions,
            Mutation::DelMDataUserPermissions { .. } => MutationType::DelMDataUserPermissions,
            Mutation::ChangeMDataOwner { .. } => MutationType::ChangeMDataOwner,
        }
    }

    /// Tests whether the two mutations conflict with each other. Conflicting
    /// mutations cannot be applied concurrently.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        match (self, other) {
            (&Mutation::MutateMDataEntries {
                 name: name0,
                 tag: tag0,
                 actions: ref actions0,
             },
             &Mutation::MutateMDataEntries {
                 name: name1,
                 tag: tag1,
                 actions: ref actions1,
             }) => name0 == name1 && tag0 == tag1 && keys_intersect(actions0, actions1),
            (_, _) => {
                if let (DataId::Mutable(id0), DataId::Mutable(id1)) =
                    (self.data_id(), other.data_id())
                {
                    id0 == id1
                } else {
                    false
                }
            }
        }
    }

    /// Apply the mutation to the mutable data, without performing any validations.
    pub fn apply(&self, data: &mut MutableData) {
        let data_id = DataId::Mutable(data.id());
        if data_id != self.data_id() {
            log_or_panic!(
                LogLevel::Error,
                "invalid data for mutation ({:?} instead of {:?})",
                data_id,
                self.data_id()
            );
            return;
        }

        match *self {
            Mutation::MutateMDataEntries { ref actions, .. } => {
                data.mutate_entries_without_validation(actions.clone())
            }
            Mutation::SetMDataUserPermissions {
                user,
                permissions,
                version,
                ..
            } => {
                let _ = data.set_user_permissions_without_validation(user, permissions, version);
            }
            Mutation::DelMDataUserPermissions { ref user, version, .. } => {
                let _ = data.del_user_permissions_without_validation(user, version);
            }
            Mutation::ChangeMDataOwner {
                ref new_owners,
                version,
                ..
            } => {
                if let Some(owner) = new_owners.iter().next() {
                    let _ = data.change_owner_without_validation(*owner, version);
                }
            }
            _ => {
                log_or_panic!(
                    LogLevel::Error,
                    "incompatible mutation ({:?})",
                    self.mutation_type()
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MutationType {
    PutIData,
    PutMData,
    MutateMDataEntries,
    SetMDataUserPermissions,
    DelMDataUserPermissions,
    ChangeMDataOwner,
}

/// Compute the size of the data after applying only those mutations that
/// increase the size.
pub fn compute_size_after_increase<'a, T>(data: &MutableData, mutations: T) -> u64
where
    T: IntoIterator<Item = &'a Mutation>,
{
    let mut size = serialised_size(data);
    let mut data = data.clone();

    for mutation in mutations {
        let mut new_data = data.clone();
        mutation.apply(&mut new_data);
        let new_size = serialised_size(&new_data);

        if new_size > size {
            size = new_size;
            data = new_data;
        }
    }

    size
}

/// Compute the number of entries after applying only those mutations that
/// increase the number of entries.
pub fn compute_entry_count_after_increase<'a, T>(data: &MutableData, mutations: T) -> u64
where
    T: IntoIterator<Item = &'a Mutation>,
{
    let prev = data.entries().len() as u64;
    let diff: u64 = mutations
        .into_iter()
        .map(|mutation| if let Mutation::MutateMDataEntries {
            ref actions, ..
        } = *mutation
        {
            count_inserts(actions)
        } else {
            0
        })
        .filter(|count| *count > 0)
        .sum();

    prev + diff
}

// Compute number of inserts in the actions.
fn count_inserts(actions: &BTreeMap<Vec<u8>, EntryAction>) -> u64 {
    actions
        .iter()
        .filter(|&(_, action)| if let EntryAction::Ins(_) = *action {
            true
        } else {
            false
        })
        .count() as u64
}

// Returns true if some of the keys in `a` are also keys in `b`.
fn keys_intersect<K: Ord, V0, V1>(a: &BTreeMap<K, V0>, b: &BTreeMap<K, V1>) -> bool {
    a.iter().any(|(key, _)| b.contains_key(key))
}

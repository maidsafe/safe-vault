// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    account_storage::AccountStorage, blob_register::BlobRegister, map_storage::MapStorage,
    sequence_storage::SequenceStorage,
};
use crate::network::Routing;

/// The various data type stores,
/// that are only managed at Elders.
pub(super) struct ElderStores<R: Routing + Clone> {
    account_storage: AccountStorage<R>,
    blob_register: BlobRegister<R>,
    map_storage: MapStorage<R>,
    sequence_storage: SequenceStorage<R>,
}

impl<R: Routing + Clone> ElderStores<R> {
    pub fn new(
        account_storage: AccountStorage<R>,
        blob_register: BlobRegister<R>,
        map_storage: MapStorage<R>,
        sequence_storage: SequenceStorage<R>,
    ) -> Self {
        Self {
            account_storage,
            blob_register,
            map_storage,
            sequence_storage,
        }
    }

    pub fn account_storage(&self) -> &AccountStorage<R> {
        &self.account_storage
    }

    pub fn blob_register(&self) -> &BlobRegister<R> {
        &self.blob_register
    }

    pub fn map_storage(&self) -> &MapStorage<R> {
        &self.map_storage
    }

    pub fn sequence_storage(&self) -> &SequenceStorage<R> {
        &self.sequence_storage
    }

    pub fn account_storage_mut(&mut self) -> &mut AccountStorage<R> {
        &mut self.account_storage
    }

    pub fn blob_register_mut(&mut self) -> &mut BlobRegister<R> {
        &mut self.blob_register
    }

    pub fn map_storage_mut(&mut self) -> &mut MapStorage<R> {
        &mut self.map_storage
    }

    pub fn sequence_storage_mut(&mut self) -> &mut SequenceStorage<R> {
        &mut self.sequence_storage
    }
}

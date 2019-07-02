// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod idata_op;

use crate::{
    account::Account,
    action::Action,
    chunk_store::{
        error::Error as ChunkStoreError, AccountChunkStore, AppendOnlyChunkStore,
        ImmutableChunkStore, MutableChunkStore,
    },
    utils,
    vault::Init,
    Result, ToDbKey,
};
use idata_op::IDataOp;
use log::{error, trace, warn};
use pickledb::PickleDb;
use safe_nd::{
    AccountData, Error as NdError, IDataAddress, IDataKind, MessageId, NodePublicId, Request,
    Response, Result as NdResult, XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{btree_map::Entry, BTreeMap},
    fmt::{self, Display, Formatter},
    iter,
    path::Path,
    rc::Rc,
};
use unwrap::unwrap;

const IMMUTABLE_META_DB_NAME: &str = "immutable_data.db";
const MUTABLE_META_DB_NAME: &str = "mutable_data.db";
const APPEND_ONLY_META_DB_NAME: &str = "append_only_data.db";
const ACCOUNT_META_DB_NAME: &str = "accounts.db";
const FULL_ADULTS_DB_NAME: &str = "full_adults.db";
// The number of separate copies of an ImmutableData chunk which should be maintained.
const IMMUTABLE_DATA_COPY_COUNT: usize = 3;

#[derive(Default, Serialize, Deserialize)]
struct ChunkMetadata {
    holders: Vec<XorName>,
}

// TODO - remove this
#[allow(unused)]
pub(crate) struct DestinationElder {
    id: NodePublicId,
    idata_ops: BTreeMap<MessageId, IDataOp>,
    immutable_metadata: PickleDb,
    mutable_metadata: PickleDb,
    append_only_metadata: PickleDb,
    account_metadata: PickleDb,
    full_adults: PickleDb,
    immutable_chunks: ImmutableChunkStore,
    mutable_chunks: MutableChunkStore,
    append_only_chunks: AppendOnlyChunkStore,
    account_chunks: AccountChunkStore,
}

impl DestinationElder {
    pub fn new<P: AsRef<Path> + Copy>(
        id: NodePublicId,
        root_dir: P,
        max_capacity: u64,
        init_mode: Init,
    ) -> Result<Self> {
        let immutable_metadata = utils::new_db(root_dir, IMMUTABLE_META_DB_NAME, init_mode)?;
        let mutable_metadata = utils::new_db(root_dir, MUTABLE_META_DB_NAME, init_mode)?;
        let append_only_metadata = utils::new_db(root_dir, APPEND_ONLY_META_DB_NAME, init_mode)?;
        let full_adults = utils::new_db(root_dir, FULL_ADULTS_DB_NAME, init_mode)?;
        let account_metadata = utils::new_db(root_dir, ACCOUNT_META_DB_NAME, init_mode)?;

        let total_used_space = Rc::new(RefCell::new(0));
        let immutable_chunks = ImmutableChunkStore::new(
            root_dir,
            max_capacity,
            Rc::clone(&total_used_space),
            init_mode,
        )?;
        let mutable_chunks = MutableChunkStore::new(
            root_dir,
            max_capacity,
            Rc::clone(&total_used_space),
            init_mode,
        )?;
        let append_only_chunks = AppendOnlyChunkStore::new(
            root_dir,
            max_capacity,
            Rc::clone(&total_used_space),
            init_mode,
        )?;
        let account_chunks = AccountChunkStore::new(
            root_dir,
            max_capacity,
            Rc::clone(&total_used_space),
            init_mode,
        )?;
        Ok(Self {
            id,
            idata_ops: Default::default(),
            immutable_metadata,
            mutable_metadata,
            append_only_metadata,
            account_metadata,
            full_adults,
            immutable_chunks,
            mutable_chunks,
            append_only_chunks,
            account_chunks,
        })
    }

    pub fn handle_request(
        &mut self,
        src: XorName,
        request: Request,
        message_id: MessageId,
    ) -> Option<Action> {
        use Request::*;
        trace!(
            "{}: Received ({:?} {:?}) from {}",
            self,
            request,
            message_id,
            src
        );
        // TODO - remove this
        #[allow(unused)]
        match request {
            //
            // ===== Immutable Data =====
            //
            PutIData(kind) => self.handle_put_idata_req(src, kind, message_id),
            GetIData(address) => self.handle_get_idata_req(src, address, message_id),
            DeleteUnpubIData(address) => unimplemented!(),
            //
            // ===== Mutable Data =====
            //
            PutUnseqMData(data) => unimplemented!(),
            PutSeqMData(data) => unimplemented!(),
            GetMData(address) => unimplemented!(),
            GetMDataValue { address, key } => unimplemented!(),
            DeleteMData(address) => unimplemented!(),
            GetMDataShell(address) => unimplemented!(),
            GetMDataVersion(address) => unimplemented!(),
            ListMDataEntries(address) => unimplemented!(),
            ListMDataKeys(address) => unimplemented!(),
            ListMDataValues(address) => unimplemented!(),
            SetMDataUserPermissions {
                address,
                user,
                permissions,
                version,
            } => unimplemented!(),
            DelMDataUserPermissions {
                address,
                user,
                version,
            } => unimplemented!(),
            ListMDataPermissions(address) => unimplemented!(),
            ListMDataUserPermissions { address, user } => unimplemented!(),
            MutateSeqMDataEntries { address, actions } => unimplemented!(),
            MutateUnseqMDataEntries { address, actions } => unimplemented!(),
            //
            // ===== Append Only Data =====
            //
            PutAData(data) => unimplemented!(),
            GetAData(address) => unimplemented!(),
            GetADataShell {
                address,
                data_index,
            } => unimplemented!(),
            DeleteAData(address) => unimplemented!(),
            GetADataRange { address, range } => unimplemented!(),
            GetADataIndices(address) => unimplemented!(),
            GetADataLastEntry(address) => unimplemented!(),
            GetADataPermissions {
                address,
                permissions_index,
            } => unimplemented!(),
            GetPubADataUserPermissions {
                address,
                permissions_index,
                user,
            } => unimplemented!(),
            GetUnpubADataUserPermissions {
                address,
                permissions_index,
                public_key,
            } => unimplemented!(),
            GetADataOwners {
                address,
                owners_index,
            } => unimplemented!(),
            AddPubADataPermissions {
                address,
                permissions,
            } => unimplemented!(),
            AddUnpubADataPermissions {
                address,
                permissions,
            } => unimplemented!(),
            SetADataOwner { address, owner } => unimplemented!(),
            AppendSeq { append, index } => unimplemented!(),
            AppendUnseq(operation) => unimplemented!(),
            //
            // ===== Coins =====
            //
            TransferCoins {
                destination,
                amount,
                transaction_id,
            } => unimplemented!(),
            GetTransaction {
                coins_balance_id,
                transaction_id,
            } => unimplemented!(),
            //
            // ===== Accounts =====
            //
            CreateAccount(ref new_account) => {
                self.handle_create_account_req(src, new_account, message_id)
            }
            UpdateAccount { .. } => unimplemented!(),
            CreateAccountFor { .. } => unimplemented!(),
            GetAccount(ref address) => self.handle_get_account_req(src, address, message_id),
            //
            // ===== Invalid =====
            //
            GetBalance
            | ListAuthKeysAndVersion
            | InsAuthKey { .. }
            | DelAuthKey { .. }
            | CreateCoinBalance { .. } => {
                error!(
                    "{}: Should not receive {:?} as a destination elder.",
                    self, request
                );
                None
            }
        }
    }

    pub fn handle_response(
        &mut self,
        src: XorName,
        response: Response,
        message_id: MessageId,
    ) -> Option<Action> {
        use Response::*;
        trace!(
            "{}: Received ({:?} {:?}) from {}",
            self,
            response,
            message_id,
            src
        );
        // TODO - remove this
        #[allow(unused)]
        match response {
            //
            // ===== Immutable Data =====
            //
            PutIData(result) => self.handle_put_idata_resp(src, result, message_id),
            GetIData(_) => self.handle_get_idata_resp(src, response, message_id),
            DeleteUnpubIData(result) => unimplemented!(),
            //
            // ===== Mutable Data =====
            //
            GetUnseqMData(result) => unimplemented!(),
            PutUnseqMData(result) => unimplemented!(),
            GetSeqMData(result) => unimplemented!(),
            PutSeqMData(result) => unimplemented!(),
            GetSeqMDataShell(result) => unimplemented!(),
            GetUnseqMDataShell(result) => unimplemented!(),
            GetMDataVersion(result) => unimplemented!(),
            ListUnseqMDataEntries(result) => unimplemented!(),
            ListSeqMDataEntries(result) => unimplemented!(),
            ListMDataKeys(result) => unimplemented!(),
            ListSeqMDataValues(result) => unimplemented!(),
            ListUnseqMDataValues(result) => unimplemented!(),
            DeleteMData(result) => unimplemented!(),
            SetMDataUserPermissions(result) => unimplemented!(),
            DelMDataUserPermissions(result) => unimplemented!(),
            ListMDataUserPermissions(result) => unimplemented!(),
            ListMDataPermissions(result) => unimplemented!(),
            MutateSeqMDataEntries(result) => unimplemented!(),
            MutateUnseqMDataEntries(result) => unimplemented!(),
            GetSeqMDataValue(result) => unimplemented!(),
            GetUnseqMDataValue(result) => unimplemented!(),
            //
            // ===== Append Only Data =====
            //
            PutAData(result) => unimplemented!(),
            GetAData(result) => unimplemented!(),
            GetADataShell(result) => unimplemented!(),
            GetADataOwners(result) => unimplemented!(),
            GetADataRange(result) => unimplemented!(),
            GetADataIndices(result) => unimplemented!(),
            GetADataLastEntry(result) => unimplemented!(),
            GetUnpubADataPermissionAtIndex(result) => unimplemented!(),
            GetPubADataPermissionAtIndex(result) => unimplemented!(),
            GetPubADataUserPermissions(result) => unimplemented!(),
            GetUnpubADataUserPermissions(result) => unimplemented!(),
            AddUnpubADataPermissions(result) => unimplemented!(),
            AddPubADataPermissions(result) => unimplemented!(),
            SetADataOwner(result) => unimplemented!(),
            AppendSeq(result) => unimplemented!(),
            AppendUnseq(result) => unimplemented!(),
            DeleteAData(result) => unimplemented!(),
            //
            // ===== Accounts ====
            //
            CreateAccount(result) => self.handle_create_account_resp(src, result, message_id),
            CreateAccount(..) | CreateAccountFor(..) | UpdateAccount(..) | GetAccount(..) => {
                unimplemented!()
            }
            //
            // ===== Invalid =====
            //
            GetTransaction(_)
            | TransferCoins(_)
            | CreateCoinBalance { .. }
            | GetBalance(_)
            | ListAuthKeysAndVersion(_)
            | InsAuthKey(_)
            | DelAuthKey(_) => {
                error!(
                    "{}: Should not receive {:?} as a destination elder.",
                    self, response
                );
                None
            }
        }
    }

    fn handle_create_account_req(
        &mut self,
        src: XorName,
        new_account: &AccountData,
        message_id: MessageId,
    ) -> Option<Action> {
        // TODO: verify owner is the same as src?
        let result = if self.account_chunks.has(&new_account.destination()) {
            Err(NdError::AccountExists)
        } else {
            self.account_chunks
                .put(&Account {
                    address: *new_account.destination(),
                    data: new_account.data().to_vec(), // FIXME: we probably don't need cloning here, try mem::replace
                    authorised_getter: *new_account.authorised_getter(),
                    signature: new_account.signature().clone(),
                })
                .map_err(|error| error.to_string().into())
        };
        Some(Action::RespondToOurDstElders {
            sender: src,
            response: Response::CreateAccount(result),
            message_id,
        })
    }

    fn handle_get_account_req(
        &mut self,
        src: XorName,
        address: &XorName,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .account_chunks
            .get(address)
            .map_err(|error| match error {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchAccount,
                error => error.to_string().into(),
            })
            .and_then(|account| {
                if XorName::from(account.authorised_getter) != src {
                    // Request does not come from the sender
                    Err(NdError::AccessDenied)
                } else {
                    Ok((account.data, account.signature))
                }
            });
        Some(Action::RespondToSrcElders {
            client_name: src,
            sender: *self.id.name(),
            response: Response::GetAccount(result),
            message_id,
        })
    }

    fn handle_create_account_resp(
        &mut self,
        client_name: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::RespondToSrcElders {
            sender: *self.id.name(),
            client_name,
            response: Response::CreateAccount(result),
            message_id,
        })
    }

    fn handle_put_idata_req(
        &mut self,
        src: XorName,
        kind: IDataKind,
        message_id: MessageId,
    ) -> Option<Action> {
        if &src == kind.name() {
            // Since the src is the chunk's name, this message was sent by the dst elders to us as a
            // single dst elder, implying that we're a dst elder chosen to store the chunk.
            self.store_idata(kind, message_id)
        } else {
            // We're acting as dst elder, received request from src elders
            // TODO - should we add the chunk to our store until we get 3 success responses, and
            //        then remove if we're not a designated holder?
            let mut metadata = ChunkMetadata::default();
            for adult in self
                .non_full_adults_sorted(kind.name())
                .take(IMMUTABLE_DATA_COPY_COUNT)
            {
                // TODO - Send Put request to adult.
                // For Routing msg, src = data.name() and dst = adult.
                metadata.holders.push(*adult);
            }
            // TODO - should we just store it right now, or wait until we get the message from our
            //        section elders?  For now, do both.
            let mut self_should_store = false;
            for elder in self
                .elders_sorted(kind.name())
                .take(IMMUTABLE_DATA_COPY_COUNT - metadata.holders.len())
            {
                metadata.holders.push(*elder);
                if elder == self.id.name() {
                    self_should_store = true;
                } else {
                    // TODO - Send Put request to elder
                    // For Routing msg, src = data.name() and dst = elder.
                }
            }
            let db_key = utils::work_arounds::idata_address(&kind).to_db_key();
            if let Err(error) = self.immutable_metadata.set(&db_key, &metadata) {
                warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                // TODO - send failure back to src elders (hopefully won't accumulate), or
                //        maybe self-terminate if we can't fix this error?
            }
            if self_should_store {
                self.store_idata(kind, message_id)
            } else {
                None
            }
        }
    }

    fn handle_put_idata_resp(
        &mut self,
        _sender: XorName,
        _result: NdResult<()>,
        _message_id: MessageId,
    ) -> Option<Action> {
        // TODO -
        // - if Ok, and this is the final of the three responses send success back to src elders and
        //   then on to the client.  Note: there's no functionality in place yet to know whether
        //   this is the last response or not.
        // - if Ok, and this is not the last response, just return `None` here.
        // - if Err, we need to flag this sender as "full" (i.e. add to self.full_adults, try on
        //   next closest non-full adult, or elder if none.  Also update the metadata for this
        //   chunk.  Not known yet where we'll get the chunk from to do that.
        //
        // For phase 1, we can leave many of these unanswered.
        unimplemented!()
    }

    fn store_idata(&mut self, kind: IDataKind, message_id: MessageId) -> Option<Action> {
        let result = if self
            .immutable_chunks
            .has(utils::work_arounds::idata_address(&kind))
        {
            Ok(())
        } else {
            self.immutable_chunks
                .put(&kind)
                .map_err(|error| error.to_string().into())
        };
        Some(Action::RespondToOurDstElders {
            sender: *self.id.name(),
            response: Response::PutIData(result),
            message_id,
        })
    }

    // Returns an iterator over all of our section's non-full adults' names, sorted by closest to
    // `target`.
    fn non_full_adults_sorted(&self, _target: &XorName) -> impl Iterator<Item = &XorName> {
        None.iter()
    }

    // Returns an iterator over all of our section's elders' names, sorted by closest to `target`.
    fn elders_sorted(&self, _target: &XorName) -> impl Iterator<Item = &XorName> {
        iter::once(self.id.name())
    }

    fn handle_get_idata_req(
        &mut self,
        src: XorName,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        if &src == address.name() {
            // The message was sent by the dst elders to us as the one who is supposed to store the
            // chunk. See the sent Get request below.
            self.get_idata(address, message_id)
        } else {
            let error_response = |error: NdError| Action::RespondToClient {
                sender: *address.name(),
                client_name: src,
                response: Response::GetIData(Err(error)),
                message_id,
            };

            // We're acting as dst elder, received request from src elders
            let metadata = if let Some(metadata) = self
                .immutable_metadata
                .get::<ChunkMetadata>(&address.to_db_key())
            {
                metadata
            } else {
                warn!("{}: Failed to get metadata from DB: {:?}", self, address);
                return Some(error_response(NdError::NoSuchData));
            };

            if metadata.holders.is_empty() {
                warn!("{}: Metadata holders is empty for: {:?}", self, address);
                return Some(error_response(NdError::NoSuchData));
            }

            // Can't fail
            let idata_op = unwrap!(IDataOp::new(
                src,
                Request::GetIData(address),
                metadata.holders.clone()
            ));
            match self.idata_ops.entry(message_id) {
                Entry::Occupied(_) => {
                    // TODO - Change to NdError::DuplicateMessageId
                    Some(error_response(NdError::NetworkOther(
                        "Duplicate Immutable data op entry detected".to_string(),
                    )))
                }
                Entry::Vacant(vacant_entry) => {
                    let idata_op = vacant_entry.insert(idata_op);
                    Some(Action::SendToPeers {
                        targets: metadata.holders,
                        request: idata_op.request().clone(),
                        message_id,
                    })
                }
            }
        }
    }

    fn get_idata(&self, address: IDataAddress, message_id: MessageId) -> Option<Action> {
        let result = self
            .immutable_chunks
            .get(&address)
            .map_err(|error| error.to_string().into())
            .map(|kind| {
                if !kind.published() {
                    // TODO - Verify ownership
                }
                kind
            });
        Some(Action::RespondToOurDstElders {
            sender: *self.id.name(),
            response: Response::GetIData(result),
            message_id,
        })
    }

    fn handle_get_idata_resp(
        &mut self,
        sender: XorName,
        response: Response,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        self.idata_ops
            .get_mut(&message_id)
            .or_else(|| {
                warn!(
                    "{}: Received response to non-existent message_id: {:?}",
                    own_id, message_id
                );
                None
            })
            .and_then(|idata_ops| idata_ops.handle_response(sender, response, own_id, message_id))
    }
}

impl Display for DestinationElder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

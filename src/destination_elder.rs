// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod idata_op;

use crate::{
    action::Action,
    chunk_store::{AppendOnlyChunkStore, ImmutableChunkStore, MutableChunkStore},
    utils,
    vault::Init,
    Result, ToDbKey,
};
use idata_op::IDataOp;
use log::{error, trace, warn};
use pickledb::PickleDb;
use safe_nd::{
    IDataAddress, IDataKind, MessageId, NodePublicId, Request, Response, Result as NdResult,
    XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    iter,
    path::Path,
    rc::Rc,
};

const IMMUTABLE_META_DB_NAME: &str = "immutable_data.db";
const MUTABLE_META_DB_NAME: &str = "mutable_data.db";
const APPEND_ONLY_META_DB_NAME: &str = "append_only_data.db";
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
    full_adults: PickleDb,
    immutable_chunks: ImmutableChunkStore,
    mutable_chunks: MutableChunkStore,
    append_only_chunks: AppendOnlyChunkStore,
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
        Ok(Self {
            id,
            idata_ops: Default::default(),
            immutable_metadata,
            mutable_metadata,
            append_only_metadata,
            full_adults,
            immutable_chunks,
            mutable_chunks,
            append_only_chunks,
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
            // ===== Invalid =====
            //
            GetBalance
            | ListAuthKeysAndVersion
            | InsAuthKey { .. }
            | DelAuthKey { .. }
            | CreateCoinBalance { .. }
            | PutAccount { .. }
            | GetAccount(..) => {
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
            GetIData(result) => self.handle_get_idata_resp(src, result, message_id),
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
            // ===== Invalid =====
            //
            GetTransaction(_)
            | TransferCoins(_)
            | CreateCoinBalance { .. }
            | GetBalance(_)
            | ListAuthKeysAndVersion(_)
            | InsAuthKey(_)
            | DelAuthKey(_)
            | PutAccount(_)
            | GetAccount(_) => {
                error!(
                    "{}: Should not receive {:?} as a destination elder.",
                    self, response
                );
                None
            }
        }
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
            // We're acting as dst elder, received request from src elders
            let metadata = if let Some(metadata) = self
                .immutable_metadata
                .get::<ChunkMetadata>(&address.to_db_key())
            {
                metadata
            } else {
                warn!("{}: Failed to get metadata from DB: {:?}", self, address);
                return None;
            };

            // TODO - Should we try the 3 holders in serial checking for responses between each
            //        send or simply broadcast and get the first response?
            // We just get the first for now. In phase 1 this is ourself anyway.
            let metadata_holder = if let Some(metadata_holder) = metadata.holders.first() {
                metadata_holder
            } else {
                warn!(
                    "{}: Failed to get location from metadata holders: {:?}",
                    self, metadata.holders
                );
                return None;
            };

            if metadata_holder == self.id.name() {
                self.get_idata(address, message_id)
            } else {
                // TODO - Send Get request to adult (or elder occasionally) with src = data.
                None
            }
        }
    }

    fn handle_get_idata_resp(
        &mut self,
        sender: XorName,
        result: NdResult<IDataKind>,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::RespondToClient {
            sender,
            response: Response::GetIData(result),
            message_id,
        })
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
}

impl Display for DestinationElder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

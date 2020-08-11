// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{error::Error as ChunkStoreError, AccountChunkStore},
    network::Routing,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::MessagingDuty,
    node::state_db::NodeInfo,
    Result,
};
use safe_nd::{
    Account, AccountRead, AccountWrite, CmdError, Error as NdError, Message, MessageId, MsgSender,
    PublicKey, QueryResponse, Result as NdResult,
};
use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};
use xor_name::XorName;

/// Operations over the data type Account.
/// NB: This type is to be deprecated, as it
/// will be handled client side at Authenticator,
/// and stored as any other data to the network.
pub(super) struct AccountStorage<R: Routing + Clone> {
    chunks: AccountChunkStore,
    wrapping: ElderMsgWrapping<R>,
}

impl<R: Routing + Clone> AccountStorage<R> {
    pub fn new(
        node_info: NodeInfo<R>,
        total_used_space: &Rc<Cell<u64>>,
        wrapping: ElderMsgWrapping<R>,
    ) -> Result<Self> {
        let chunks = AccountChunkStore::new(
            node_info.path(),
            node_info.max_storage_capacity,
            Rc::clone(total_used_space),
            node_info.init_mode,
        )?;
        Ok(Self { chunks, wrapping })
    }

    pub(super) fn read(
        &self,
        read: &AccountRead,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        use AccountRead::*;
        match read {
            Get(ref address) => self.get(address, msg_id, origin),
        }
    }

    fn get(
        &self,
        address: &XorName,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .account(&origin.id(), address)
            .map(Account::into_data_and_signature);
        self.wrapping.send(Message::QueryResponse {
            id: MessageId::new(),
            response: QueryResponse::GetAccount(result),
            correlation_id: msg_id,
            query_origin: origin.address(),
        })
    }

    pub(super) fn write(
        &mut self,
        write: AccountWrite,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        use AccountWrite::*;
        match write {
            New(ref account) => self.create(account, msg_id, &origin),
            Update(updated_account) => self.update(&updated_account, msg_id, &origin),
        }
    }

    fn create(
        &mut self,
        account: &Account,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = if self.chunks.has(account.address()) {
            Err(NdError::LoginPacketExists)
        } else if account.owner() != &origin.id() {
            Err(NdError::InvalidOwners)
        } else {
            // also check the signature
            self.chunks
                .put(account)
                .map_err(|error| error.to_string().into())
        };
        self.ok_or_error(result, msg_id, &origin)
    }

    fn update(
        &mut self,
        updated_account: &Account,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .account(&origin.id(), updated_account.address())
            .and_then(|existing_account| {
                if !updated_account.size_is_valid() {
                    Err(NdError::ExceededSize)
                } else if updated_account.owner() != existing_account.owner() {
                    Err(NdError::InvalidOwners)
                } else {
                    // also check the signature
                    self.chunks
                        .put(&updated_account)
                        .map_err(|err| err.to_string().into())
                }
            });
        self.ok_or_error(result, msg_id, &origin)
    }

    fn account(&self, requester_pub_key: &PublicKey, address: &XorName) -> NdResult<Account> {
        self.chunks
            .get(address)
            .map_err(|e| match e {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchLoginPacket,
                error => error.to_string().into(),
            })
            .and_then(|account| {
                if account.owner() == requester_pub_key {
                    Ok(account)
                } else {
                    Err(NdError::AccessDenied)
                }
            })
    }

    fn ok_or_error(
        &self,
        result: NdResult<()>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        if let Err(error) = result {
            return self.wrapping.send(Message::CmdError {
                id: MessageId::new(),
                error: CmdError::Data(error),
                correlation_id: msg_id,
                cmd_origin: origin.address(),
            });
        }
        None
    }
}

impl<R: Routing + Clone> Display for AccountStorage<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "AccountStorage")
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{error::Error as ChunkStoreError, AccountChunkStore, UsedSpace},
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::NodeMessagingDuty,
    node::state_db::NodeInfo,
    Result,
};
use sn_data_types::{
    Account, AccountRead, AccountWrite, CmdError, Error as NdError, Message, MessageId, MsgSender,
    PublicKey, QueryResponse, Result as NdResult,
};
use std::fmt::{self, Display, Formatter};
use xor_name::XorName;

/// Operations over the data type Account.
/// NB: This type is to be deprecated, as it
/// will be handled client side at Authenticator,
/// and stored as any other data to the network.
pub(super) struct AccountStorage {
    chunks: AccountChunkStore,
    wrapping: ElderMsgWrapping,
}

impl AccountStorage {
    pub async fn new(
        node_info: &NodeInfo,
        used_space: UsedSpace,
        wrapping: ElderMsgWrapping,
    ) -> Result<Self> {
        let chunks =
            AccountChunkStore::new(node_info.path(), used_space, node_info.init_mode).await?;
        Ok(Self { chunks, wrapping })
    }

    pub(super) async fn read(
        &self,
        read: &AccountRead,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        use AccountRead::*;
        match read {
            Get(ref address) => self.get(address, msg_id, origin).await,
        }
    }

    async fn get(
        &self,
        address: &XorName,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .account(&origin.id(), address)
            .map(Account::into_data_and_signature);
        self.wrapping
            .send(Message::QueryResponse {
                id: MessageId::new(),
                response: QueryResponse::GetAccount(result),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    pub(super) async fn write(
        &mut self,
        write: AccountWrite,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        use AccountWrite::*;
        match write {
            New(ref account) => self.create(account, msg_id, &origin).await,
            Update(updated_account) => self.update(&updated_account, msg_id, &origin).await,
        }
    }

    async fn create(
        &mut self,
        account: &Account,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = if self.chunks.has(account.address()) {
            Err(NdError::LoginPacketExists)
        } else if account.owner() != &origin.id() {
            Err(NdError::InvalidOwners)
        } else {
            // also check the signature
            self.chunks
                .put(account)
                .await
                .map_err(|error| error.to_string().into())
        };
        self.ok_or_error(result, msg_id, &origin).await
    }

    async fn update(
        &mut self,
        updated_account: &Account,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = match self.account(&origin.id(), updated_account.address()) {
            Ok(existing_account) => {
                if !updated_account.size_is_valid() {
                    Err(NdError::ExceededSize)
                } else if updated_account.owner() != existing_account.owner() {
                    Err(NdError::InvalidOwners)
                } else {
                    // also check the signature
                    self.chunks
                        .put(&updated_account)
                        .await
                        .map_err(|err| err.to_string().into())
                }
            }
            Err(error) => Err(error),
        };
        self.ok_or_error(result, msg_id, &origin).await
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

    async fn ok_or_error(
        &self,
        result: NdResult<()>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        if let Err(error) = result {
            return self
                .wrapping
                .send(Message::CmdError {
                    id: MessageId::new(),
                    error: CmdError::Data(error),
                    correlation_id: msg_id,
                    cmd_origin: origin.address(),
                })
                .await;
        }
        None
    }
}

impl Display for AccountStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "AccountStorage")
    }
}

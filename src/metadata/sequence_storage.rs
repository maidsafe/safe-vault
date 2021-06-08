// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{build_client_error_response, build_client_query_response};
use crate::{
    chunk_store::SequenceChunkStore, error::convert_to_error_message, node_ops::NodeDuty, Error,
    Result,
};
use log::{debug, info};
use sn_data_types::{
    Error as DtError, PublicKey, Sequence, SequenceAction, SequenceAddress, SequenceEntry,
    SequenceIndex, SequenceOp, SequenceUser,
};
use sn_messaging::{
    client::{CmdError, QueryResponse, SequenceDataExchange, SequenceRead, SequenceWrite},
    EndUser, MessageId,
};
use sn_routing::Prefix;
use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};

/// Operations over the data type Sequence.
pub(super) struct SequenceStorage {
    chunks: SequenceChunkStore,
}

impl SequenceStorage {
    pub(super) async fn new(path: &Path, max_capacity: u64) -> Result<Self> {
        let chunks = SequenceChunkStore::new(path, max_capacity).await?;
        Ok(Self { chunks })
    }

    pub fn get_data_of(&self, prefix: Prefix) -> SequenceDataExchange {
        let store = &self.chunks;
        let data = self
            .chunks
            .keys()
            .iter()
            .filter(|address| prefix.matches(address.name()))
            .filter_map(|key| store.get(&key).ok())
            .map(|seq| (*seq.address(), seq))
            .collect();
        SequenceDataExchange(data)
    }

    pub async fn update(&mut self, seq_data: SequenceDataExchange) -> Result<()> {
        debug!("Updating Sequence chunkstore");
        let chunkstore = &mut self.chunks;
        let SequenceDataExchange(data) = seq_data;

        for (_key, value) in data {
            chunkstore.put(&value).await?;
        }

        Ok(())
    }

    pub(super) async fn read(
        &self,
        read: &SequenceRead,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use SequenceRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, requester, origin).await,
            GetRange { address, range } => {
                self.get_range(*address, *range, msg_id, requester, origin)
                    .await
            }
            GetLastEntry(address) => {
                self.get_last_entry(*address, msg_id, requester, origin)
                    .await
            }
            GetUserPermissions { address, user } => {
                self.get_user_permissions(*address, *user, msg_id, requester, origin)
                    .await
            }
            GetPublicPolicy(address) => {
                self.get_public_policy(*address, msg_id, requester, origin)
                    .await
            }
            GetPrivatePolicy(address) => {
                self.get_private_policy(*address, msg_id, requester, origin)
                    .await
            }
        }
    }

    pub(super) async fn write(
        &mut self,
        write: SequenceWrite,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use SequenceWrite::*;
        info!("Matching Sequence Write");
        match write {
            New(data) => self.store(&data, msg_id, origin).await,
            Edit(operation) => {
                info!("Editing Sequence");
                self.edit(operation, msg_id, requester, origin).await
            }
            Delete(address) => self.delete(address, msg_id, requester, origin).await,
        }
    }

    async fn store(
        &mut self,
        data: &Sequence,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(Error::DataExists)
        } else {
            self.chunks.put(&data).await
        };
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn get(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.get_chunk(address, SequenceAction::Read, requester) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };
        Ok(NodeDuty::Send(build_client_query_response(
            QueryResponse::GetSequence(result),
            msg_id,
            origin,
        )))
    }

    fn get_chunk(
        &self,
        address: SequenceAddress,
        action: SequenceAction,
        requester: PublicKey,
    ) -> Result<Sequence> {
        let data = self.chunks.get(&address)?;
        data.check_permission(action, Some(requester))?;
        Ok(data)
    }

    async fn delete(
        &mut self,
        address: SequenceAddress,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.chunks.get(&address).and_then(|sequence| {
            // TODO - Sequence::check_permission() doesn't support Delete yet in safe-nd
            if sequence.address().is_public() {
                return Err(Error::InvalidMessage(
                    msg_id,
                    "Sequence::check_permission() doesn't support Delete yet in safe-nd"
                        .to_string(),
                ));
            }

            let policy = sequence.private_policy(Some(requester))?;
            if requester != policy.owner {
                Err(Error::InvalidOwner(requester))
            } else {
                Ok(())
            }
        }) {
            Ok(()) => self.chunks.delete(&address).await,
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, origin).await
    }

    async fn get_range(
        &self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, requester)
            .and_then(|sequence| {
                sequence
                    .in_range(range.0, range.1, Some(requester))?
                    .ok_or(Error::NetworkData(DtError::NoSuchEntry))
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(build_client_query_response(
            QueryResponse::GetSequenceRange(result),
            msg_id,
            origin,
        )))
    }

    async fn get_last_entry(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, requester)
            .and_then(|sequence| match sequence.last_entry(Some(requester))? {
                Some(entry) => Ok((sequence.len(Some(requester))? - 1, entry.to_vec())),
                None => Err(Error::NetworkData(DtError::NoSuchEntry)),
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(build_client_query_response(
            QueryResponse::GetSequenceLastEntry(result),
            msg_id,
            origin,
        )))
    }

    async fn get_user_permissions(
        &self,
        address: SequenceAddress,
        user: SequenceUser,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, requester)
            .and_then(|sequence| {
                sequence
                    .permissions(user, Some(requester))
                    .map_err(|e| e.into())
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(build_client_query_response(
            QueryResponse::GetSequenceUserPermissions(result),
            msg_id,
            origin,
        )))
    }

    async fn get_public_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, requester)
            .and_then(|sequence| {
                let res = if sequence.is_public() {
                    let policy = sequence.public_policy()?;
                    policy.clone()
                } else {
                    return Err(Error::NetworkData(DtError::CrdtUnexpectedState));
                };
                Ok(res)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(build_client_query_response(
            QueryResponse::GetSequencePublicPolicy(result),
            msg_id,
            origin,
        )))
    }

    async fn get_private_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, requester)
            .and_then(|sequence| {
                let res = if !sequence.is_public() {
                    let policy = sequence.private_policy(Some(requester))?;
                    policy.clone()
                } else {
                    return Err(Error::NetworkData(DtError::CrdtUnexpectedState));
                };
                Ok(res)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(build_client_query_response(
            QueryResponse::GetSequencePrivatePolicy(result),
            msg_id,
            origin,
        )))
    }

    async fn edit(
        &mut self,
        write_op: SequenceOp<SequenceEntry>,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let address = write_op.address;
        info!("Editing Sequence chunk");
        let result = self
            .edit_chunk(
                address,
                SequenceAction::Append,
                requester,
                move |mut sequence| {
                    sequence.apply_op(write_op)?;
                    Ok(sequence)
                },
            )
            .await;
        if result.is_ok() {
            info!("Editing Sequence chunk SUCCESSFUL!");
        } else {
            info!("Editing Sequence chunk FAILEDDD!");
        }
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn edit_chunk<F>(
        &mut self,
        address: SequenceAddress,
        action: SequenceAction,
        requester: PublicKey,
        write_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(Sequence) -> Result<Sequence>,
    {
        info!("Getting Sequence chunk for Edit");
        let result = self.get_chunk(address, action, requester)?;
        let sequence = write_fn(result)?;
        info!("Edited Sequence chunk successfully");
        self.chunks.put(&sequence).await
    }

    async fn ok_or_error<T>(
        &self,
        result: Result<T>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let error = match result {
            Ok(_) => return Ok(NodeDuty::NoOp),
            Err(error) => {
                info!("Error on writing Sequence! {:?}", error);
                convert_to_error_message(error)
            }
        };

        Ok(NodeDuty::Send(build_client_error_response(
            CmdError::Data(error),
            msg_id,
            origin,
        )))
    }
}

impl Display for SequenceStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SequenceStorage")
    }
}

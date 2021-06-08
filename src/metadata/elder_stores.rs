// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    blob_records::BlobRecords, map_storage::MapStorage, register_storage::RegisterStorage,
    sequence_storage::SequenceStorage,
};
use crate::{node_ops::NodeDuty, Error, Result};
use log::info;
use sn_data_types::PublicKey;
use sn_messaging::{
    client::{ClientSigned, DataCmd, DataExchange, DataQuery},
    EndUser, MessageId,
};
use sn_routing::Prefix;

/// The various data type stores,
/// that are only managed at Elders.
pub(super) struct ElderStores {
    blob_records: BlobRecords,
    map_storage: MapStorage,
    sequence_storage: SequenceStorage,
    register_storage: RegisterStorage,
}

impl ElderStores {
    pub fn new(
        blob_records: BlobRecords,
        map_storage: MapStorage,
        sequence_storage: SequenceStorage,
        register_storage: RegisterStorage,
    ) -> Self {
        Self {
            blob_records,
            map_storage,
            sequence_storage,
            register_storage,
        }
    }

    pub async fn read(
        &mut self,
        query: DataQuery,
        msg_id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        match &query {
            DataQuery::Blob(read) => self.blob_records.read(read, msg_id, origin).await,
            DataQuery::Map(read) => self.map_storage.read(read, msg_id, requester, origin).await,
            DataQuery::Sequence(read) => {
                self.sequence_storage
                    .read(read, msg_id, requester, origin)
                    .await
            }
            DataQuery::Register(read) => {
                self.register_storage
                    .read(read, msg_id, requester, origin)
                    .await
            }
        }
    }

    pub async fn write(
        &mut self,
        cmd: DataCmd,
        msg_id: MessageId,
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        info!("Writing Data");
        match cmd {
            DataCmd::Blob(write) => {
                info!("Writing Blob");
                self.blob_records
                    .write(write, msg_id, client_signed, origin)
                    .await
            }
            DataCmd::Map(write) => {
                info!("Writing Map");
                self.map_storage
                    .write(write, msg_id, client_signed.public_key, origin)
                    .await
            }
            DataCmd::Sequence(write) => {
                info!("Writing Sequence");
                self.sequence_storage
                    .write(write, msg_id, client_signed.public_key, origin)
                    .await
            }
            DataCmd::Register(write) => {
                info!("Writing Register");
                self.register_storage
                    .write(write, msg_id, client_signed.public_key, origin)
                    .await
            }
        }
    }

    pub fn blob_records_mut(&mut self) -> &mut BlobRecords {
        &mut self.blob_records
    }

    // NB: Not yet including Register metadata.
    pub async fn get_data_of(&self, prefix: Prefix) -> Result<DataExchange> {
        // Prepare blob_records, map and sequence data
        let blob_data = self.blob_records.get_data_of(prefix).await;
        let map_data = self.map_storage.get_data_of(prefix);
        let seq_data = self.sequence_storage.get_data_of(prefix);

        Ok(DataExchange {
            blob_data,
            map_data,
            seq_data,
        })
    }

    pub async fn update(&mut self, data: DataExchange) -> Result<(), Error> {
        self.map_storage.update(data.map_data).await?;
        self.sequence_storage.update(data.seq_data).await?;
        self.blob_records.update(data.blob_data).await;

        Ok(())
    }
}

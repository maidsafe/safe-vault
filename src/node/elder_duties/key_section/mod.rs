// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client;
mod client_msg_analysis;
mod payment;
mod transfers;

use self::{
    client::ClientGateway,
    client_msg_analysis::ClientMsgAnalysis,
    payment::Payments,
    transfers::{replica_manager::ReplicaManager, store::TransferStore, Transfers},
};
use crate::{
    capacity::RateLimit,
    node::node_ops::{KeySectionDuty, NodeOperation},
    node::state_db::NodeInfo,
    Network, Result,
};
use futures::lock::Mutex;
use log::{error, trace};
use rand::{CryptoRng, Rng};
use sn_data_types::PublicKey;
use sn_routing::Prefix;
use std::collections::BTreeSet;
use std::sync::Arc;
use xor_name::XorName;

/// A Key Section interfaces with clients,
/// who are essentially a public key,
/// (hence the name Key Section), used by
/// a specific socket address.
/// The Gateway deals with onboarding (handshakes etc)
/// and routing messages back and forth to clients.
/// Payments deals with the payment for data writes,
/// while transfers deals with sending money between keys.
pub struct KeySection<R: CryptoRng + Rng> {
    gateway: ClientGateway<R>,
    payments: Payments,
    transfers: Transfers,
    msg_analysis: ClientMsgAnalysis,
    replica_manager: Arc<Mutex<ReplicaManager>>,
    routing: Network,
}

impl<R: CryptoRng + Rng> KeySection<R> {
    pub async fn new(
        info: &NodeInfo,
        rate_limit: RateLimit,
        routing: Network,
        rng: R,
    ) -> Result<Self> {
        let gateway = ClientGateway::new(info, routing.clone(), rng).await?;
        let replica_manager = Self::new_replica_manager(info, routing.clone(), rate_limit).await?;
        let payments = Payments::new(info.keys.clone(), replica_manager.clone());
        let transfers = Transfers::new(info.keys.clone(), replica_manager.clone());
        let msg_analysis = ClientMsgAnalysis::new(routing.clone());

        Ok(Self {
            gateway,
            payments,
            transfers,
            msg_analysis,
            replica_manager,
            routing,
        })
    }

    /// Initiates as first node in a network.
    pub async fn init_first(&mut self) -> Option<NodeOperation> {
        self.transfers.init_first().await
    }

    /// Issues queries to Elders of the section
    /// as to catch up with shares state and
    /// start working properly in the group.
    pub async fn catchup_with_section(&mut self) -> Option<NodeOperation> {
        // currently only at2 replicas need to catch up
        self.transfers.catchup_with_replicas().await
    }

    // Update our replica with the latest keys
    pub async fn elders_changed(&mut self) -> Option<NodeOperation> {
        let pub_key_set = self.routing.public_key_set().await.ok()?;
        let sec_key_share = self.routing.secret_key_share().await.ok()?;
        let proof_chain = self.routing.our_history().await;
        let index = self.routing.our_index().await.ok()?;
        match self.replica_manager.lock().await.update_replica_keys(
            sec_key_share,
            index,
            pub_key_set,
            proof_chain,
        ) {
            Ok(()) => None,
            Err(e) => {
                error!("Error at elders changed event.... panic happens");
                panic!(e)
            } // Temporary brittle solution before lazy messaging impl.
        }
    }

    /// When section splits, the Replicas in either resulting section
    /// also split the responsibility of the accounts.
    /// Thus, both Replica groups need to drop the accounts that
    /// the other group is now responsible for.
    pub async fn section_split(&mut self, prefix: Prefix) -> Option<NodeOperation> {
        // Removes accounts that are no longer our section responsibility.
        let not_matching = |key: PublicKey| {
            let xorname: XorName = key.into();
            !prefix.matches(&XorName(xorname.0))
        };
        let all_keys = self.replica_manager.lock().await.all_keys()?;
        let accounts = all_keys
            .iter()
            .filter(|key| not_matching(**key))
            .copied()
            .collect::<BTreeSet<PublicKey>>();
        self.replica_manager
            .lock()
            .await
            .drop_accounts(&accounts)
            .ok()?;
        None
    }

    pub async fn process_key_section_duty(
        &mut self,
        duty: KeySectionDuty,
    ) -> Option<NodeOperation> {
        trace!("Processing as Elder KeySection");
        use KeySectionDuty::*;
        match duty {
            EvaluateClientMsg(msg) => self.msg_analysis.evaluate(&msg).await,
            RunAsGateway(duty) => self.gateway.process_as_gateway(duty).await,
            RunAsPayment(duty) => self.payments.process_payment_duty(&duty).await,
            RunAsTransfers(duty) => self.transfers.process_transfer_duty(&duty).await,
        }
    }

    async fn new_replica_manager(
        info: &NodeInfo,
        routing: Network,
        rate_limit: RateLimit,
    ) -> Result<Arc<Mutex<ReplicaManager>>> {
        let public_key_set = routing.public_key_set().await?;
        let secret_key_share = routing.secret_key_share().await?;
        let key_index = routing.our_index().await?;
        let proof_chain = routing.our_history().await;
        let store = TransferStore::new(info.root_dir.clone(), info.init_mode)?;
        let replica_manager = ReplicaManager::new(
            store,
            &secret_key_share,
            key_index,
            rate_limit,
            &public_key_set,
            proof_chain,
        )?;
        Ok(Arc::new(Mutex::new(replica_manager)))
    }
}

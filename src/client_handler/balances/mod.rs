// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod db;

pub use self::db::{Balance, BalancesDb};
use super::COST_OF_PUT;
use crate::{
    action::{Action, ConsensusAction},
    rpc::Rpc,
    utils, Result,
};
use log::{error, info, trace};
use safe_nd::{
    Coins, Error as NdError, MessageId, NodePublicId, PublicId, PublicKey, Request, Response,
    Transaction, TransactionId, XorName,
};
use std::fmt::{self, Display, Formatter};

pub struct Balances {
    id: NodePublicId,
    db: BalancesDb,
}

impl Balances {
    pub fn new(id: NodePublicId, db: BalancesDb) -> Self {
        Self { id, db }
    }

    pub(super) fn initiate_creation(
        &mut self,
        requester: &PublicId,
        owner_key: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
        message_id: MessageId,
    ) -> Option<Action> {
        let request = Request::CreateBalance {
            new_balance_owner: owner_key,
            amount,
            transaction_id,
        };
        // For phases 1 & 2 we allow owners to create their own balance freely.
        let own_request = utils::own_key(requester)
            .map(|key| key == &owner_key)
            .unwrap_or(false);
        if own_request {
            return Some(Action::VoteFor(ConsensusAction::Forward {
                request,
                client_public_id: requester.clone(),
                message_id,
            }));
        }

        let total_amount = amount.checked_add(COST_OF_PUT)?;
        // When ClientA(owner/app with permissions) creates a balance for ClientB
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: requester.clone(),
            message_id,
            cost: total_amount,
        }))
    }

    pub(super) fn finalize_creation(
        &mut self,
        requester: PublicId,
        owner_key: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
        message_id: MessageId,
    ) -> Option<Action> {
        let (result, refund) = match self.create(&requester, owner_key, amount) {
            Ok(()) => {
                let transaction = Transaction {
                    id: transaction_id,
                    amount,
                };
                (Ok(transaction), None)
            }
            Err(error) => {
                // Refund amount (Including the cost of creating a balance)
                let amount = amount.checked_add(COST_OF_PUT)?;
                (Err(error), Some(amount))
            }
        };

        Some(Action::RespondToClientHandlers {
            sender: *self.id.name(),
            rpc: Rpc::Response {
                response: Response::Transaction(result),
                requester,
                message_id,
                refund,
            },
        })
    }

    pub(super) fn initiate_transfer(
        &mut self,
        requester: &PublicId,
        destination: XorName,
        amount: Coins,
        transaction_id: TransactionId,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request: Request::TransferCoins {
                destination,
                amount,
                transaction_id,
            },
            client_public_id: requester.clone(),
            message_id,
            cost: amount,
        }))
    }

    pub(super) fn finalize_transfer(
        &mut self,
        requester: PublicId,
        destination: XorName,
        amount: Coins,
        transaction_id: TransactionId,
        message_id: MessageId,
    ) -> Option<Action> {
        let (result, refund) = match self.deposit(&destination, amount) {
            Ok(()) => {
                let transaction = Transaction {
                    id: transaction_id,
                    amount,
                };

                (Ok(transaction), None)
            }
            Err(error) => (Err(error), Some(amount)),
        };

        Some(Action::RespondToClientHandlers {
            sender: *self.id.name(),
            rpc: Rpc::Response {
                response: Response::Transaction(result),
                requester,
                message_id,
                refund,
            },
        })
    }

    pub(super) fn deposit<K: db::Key>(&mut self, key: &K, amount: Coins) -> Result<(), NdError> {
        let (public_key, mut balance) = self
            .db
            .get_key_value(key)
            .ok_or_else(|| NdError::NoSuchBalance)?;
        balance.coins = balance
            .coins
            .checked_add(amount)
            .ok_or(NdError::ExcessiveValue)?;

        self.set(&public_key, &balance)
    }

    // Pays cost of a request.
    pub(super) fn pay(
        &mut self,
        requester_id: &PublicId,
        requester_key: &PublicKey,
        request: &Request,
        message_id: MessageId,
        cost: Coins,
    ) -> Option<Action> {
        trace!("{}: {} is paying {} coins", self, requester_id, cost);
        match self.withdraw(requester_key, cost) {
            Ok(()) => None,
            Err(error) => {
                trace!("{}: Unable to withdraw {} coins: {}", self, cost, error);
                Some(Action::RespondToClient {
                    message_id,
                    response: request.error_response(error),
                })
            }
        }
    }

    pub(super) fn get<K: db::Key>(&self, key: &K) -> Option<Coins> {
        self.db.get(key).map(|balance| balance.coins)
    }

    pub(super) fn create(
        &mut self,
        requester: &PublicId,
        owner_key: PublicKey,
        amount: Coins,
    ) -> Result<(), NdError> {
        let own_request = utils::own_key(requester)
            .map(|key| key == &owner_key)
            .unwrap_or(false);
        if !own_request && self.db.exists(&owner_key) {
            info!(
                "{}: Failed to create balance for {:?}: already exists.",
                self, owner_key
            );

            Err(NdError::BalanceExists)
        } else {
            let balance = Balance { coins: amount };
            self.set(&owner_key, &balance)?;
            Ok(())
        }
    }

    fn set(&mut self, public_key: &PublicKey, balance: &Balance) -> Result<(), NdError> {
        trace!(
            "{}: Setting balance to {} for {}",
            self,
            balance,
            public_key
        );
        self.db.set(public_key, balance).map_err(|error| {
            error!(
                "{}: Failed to set balance of {}: {}",
                self, public_key, error
            );

            NdError::from("Failed to set balance")
        })
    }

    fn withdraw<K: db::Key>(&mut self, key: &K, amount: Coins) -> Result<(), NdError> {
        if amount.as_nano() == 0 {
            return Err(NdError::InvalidOperation);
        }
        let (public_key, mut balance) = self.db.get_key_value(key).ok_or(NdError::NoSuchBalance)?;
        balance.coins = balance
            .coins
            .checked_sub(amount)
            .ok_or(NdError::InsufficientBalance)?;
        self.set(&public_key, &balance)
    }
}

impl Display for Balances {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_farming::{Accumulation, AccumulationEvent, RewardAlgo};
use safe_nd::{AccountId, Money, Result, RewardCounter, Work};
use std::collections::HashMap;

pub struct FarmingSystem<A: RewardAlgo> {
    farming_algo: A,
    accumulation: Accumulation,
}

#[allow(unused)]
impl<A: RewardAlgo> FarmingSystem<A> {
    ///
    pub fn new(farming_algo: A, accumulation: Accumulation) -> Self {
        Self {
            farming_algo,
            accumulation,
        }
    }

    /// Work is the total work associated with this account id.
    /// It is a strictly incrementing value during the lifetime of
    /// the owner on the network.
    pub fn add_account(&mut self, id: AccountId, work: Work) -> Result<()> {
        let e = self.accumulation.add_account(id, work)?;
        self.accumulation.apply(AccumulationEvent::AccountAdded(e));
        Ok(())
    }

    pub fn set_base_cost(&mut self, base_cost: Money) {
        self.farming_algo.set(base_cost)
    }

    /// Factor is a number > 0, by which reward will be increased or decreased.
    /// When factor == 1, there is no scaling of the rewards.
    /// When factor is > 1, the reward is scaled up.
    /// When factor is < 1, the reward is scaled down.
    ///
    /// Temp comments for the SAFE Network farming context:
    ///
    /// When factor is > 1, the StoreCost is - effectively - topped up with the surplus
    /// from section account, to form the total reward.
    /// This is essentially the same as a _net farming_, aka net issuance of money.
    ///
    /// When factor is < 1, the excess from the StoreCost
    /// stays at the section account.
    /// This is essentially the same as recycling money, moving it out of circulation.
    ///
    /// The factor is thus the adjustment of total supply in circulation vs total amount held by the network.
    /// It's envisaged that the calculation of this factor, is where the crux of balancing the network economy is,
    /// and where we will see changes due to tweaks, bug fixes, and improvements.
    /// With other words: that is code that will change with a higher rate than this code, and is thus
    /// separated out, for some other layer to deal with.
    ///
    /// The factor is the output of a function of parameters
    /// relevant to the implementing layer.
    /// In SAFE Network context, those parameters could be node count,
    /// section count, percent filled etc. etc.
    pub fn reward(&mut self, reward_id: Vec<u8>, num_bytes: u64, factor: f64) -> Result<Money> {
        // First query for accumulated work of all.
        let accounts_work: HashMap<AccountId, Work> = self
            .accumulation
            .get_all()
            .iter()
            .map(|(id, acc)| (*id, acc.work))
            .collect();
        // Calculate the work cost for the number of bytes to store.
        let work_cost = self.farming_algo.work_cost(num_bytes);
        // Scale the reward by the factor.
        let total_reward = self.farming_algo.total_reward(factor, work_cost);
        // Distribute according to previously performed work.
        let distribution = self.farming_algo.distribute(total_reward, accounts_work);

        // Validate the operation.
        let e = self.accumulation.accumulate(reward_id, distribution)?;

        // Apply the result. Reward counters are now incremented
        // i.e. both the reward amount and the work performed.
        self.accumulation
            .apply(AccumulationEvent::RewardsAccumulated(e));

        Ok(total_reward)
    }

    pub fn claim(&mut self, id: AccountId) -> Result<RewardCounter> {
        let e = self.accumulation.claim(id)?;
        self.accumulation
            .apply(AccumulationEvent::RewardsClaimed(e.clone()));
        Ok(e.rewards)
    }
}

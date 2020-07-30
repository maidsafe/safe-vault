// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_nd::{Money, PublicKey};

/// An indicator is used to calculate
/// the minting metrics. The period cost base
/// is used together with delta writes, to get
/// current store cost. The velocity is a scaling
/// factor which determines the net money issuance.
#[derive(Clone)]
pub struct Indicator {
    /// The current BLS key of the section.
    pub period_key: PublicKey,
    /// The velocity is a scaling
    /// factor which determines the net money issuance.
    pub minting_velocity: f64,
    /// Used to calculate the store cost
    /// to be used during a period
    /// (i.e. a specific Elder constellation).
    pub period_base_cost: Money,
}

/// MintingMetrics are valid through
/// the lifetime of a specific Elder
/// constellation.
/// At every Elder membership change
/// there is a new public key, and a new
/// calculation of store cost and minting velocity.
#[derive(Clone, Debug)]
pub struct MintingMetrics {
    /// The current BLS key of the section.
    pub key: PublicKey,
    /// The base cost for the period, weighted by the load delta compared to previous period,
    /// (i.e. the specific Elder constellation represented by the PublicKey).
    pub store_cost: Money,
    /// The velocity is a scaling
    /// factor which determines the net money issuance.
    pub velocity: f64,
}

// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::utils;
use base64;
use safe_nd::{
    Address, ClientPublicId, IDataAddress, MDataAddress, NodePublicId, PublicKey, XorName,
};
use serde::Serialize;

pub(crate) trait ToDbKey: Serialize {
    /// The encoded string representation of an identifier, used as a key in the context of a
    /// PickleDB <key,value> store.
    fn to_db_key(&self) -> String {
        let serialised = utils::serialise(&self);
        base64::encode(&serialised)
    }
}

impl ToDbKey for Address {}
impl ToDbKey for ClientPublicId {}
impl ToDbKey for IDataAddress {}
impl ToDbKey for MDataAddress {}
impl ToDbKey for NodePublicId {}
impl ToDbKey for PublicKey {}
impl ToDbKey for XorName {}

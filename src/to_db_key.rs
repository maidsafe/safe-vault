// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::utils;
use base64;
use safe_nd::{
    ADataAddress, ClientPublicId, IDataAddress, MDataAddress, NodePublicId, PublicKey, XorName,
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

impl ToDbKey for ADataAddress {}
impl ToDbKey for ClientPublicId {}
impl ToDbKey for IDataAddress {}
impl ToDbKey for MDataAddress {}
impl ToDbKey for NodePublicId {}
impl ToDbKey for PublicKey {}
impl ToDbKey for XorName {}

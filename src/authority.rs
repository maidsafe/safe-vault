// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use routing::{Authority, PublicId, XorName};
use rust_sodium::crypto::sign;

/// Client.
#[derive(Debug, Clone, Copy)]
pub struct ClientAuthority {
    pub client_id: PublicId,
    pub proxy_node_name: XorName,
}

impl ClientAuthority {
    pub fn name(&self) -> &XorName {
        self.client_id.name()
    }

    pub fn client_key(&self) -> &sign::PublicKey {
        self.client_id.signing_public_key()
    }
}

impl From<ClientAuthority> for Authority<XorName> {
    fn from(auth: ClientAuthority) -> Self {
        Authority::Client {
            client_id: auth.client_id,
            proxy_node_name: auth.proxy_node_name,
        }
    }
}

/// Client manager
#[derive(Debug, Clone, Copy)]
pub struct ClientManagerAuthority(pub XorName);

impl ClientManagerAuthority {
    pub fn name(&self) -> &XorName {
        &self.0
    }
}

impl From<ClientManagerAuthority> for Authority<XorName> {
    fn from(auth: ClientManagerAuthority) -> Self {
        Authority::ClientManager(auth.0)
    }
}

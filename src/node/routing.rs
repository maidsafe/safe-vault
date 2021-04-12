// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{network::Network, Result};
use crate::{node_ops::OutgoingMsg, Error};
use log::{error, trace};
use sn_messaging::{client::Message, Aggregation, DstLocation, Itinerary, SrcLocation};
use sn_routing::XorName;
use std::collections::BTreeSet;

pub(crate) async fn send(msg: OutgoingMsg, network: &Network) -> Result<()> {
    let our_prefix = network.our_prefix().await;
    trace!("{:?}, Sending msg: {:?}", our_prefix, msg);
    let src = if msg.section_source {
        SrcLocation::Section(our_prefix.name())
    } else {
        SrcLocation::Node(network.our_name().await)
    };
    let itinerary = Itinerary {
        src,
        dst: msg.dst,
        aggregation: msg.aggregation,
    };
    let result = network.send_message(itinerary, msg.msg.serialize()?).await;

    result.map_or_else(
        |err| {
            error!("Unable to send msg: {:?}", err);
            Err(Error::Logic(format!("Unable to send msg: {:?}", msg.id())))
        },
        |()| Ok(()),
    )
}

pub(crate) async fn send_to_nodes(
    msg: &Message,
    targets: BTreeSet<XorName>,
    aggregation: Aggregation,
    network: &Network,
) -> Result<()> {
    let our_prefix = network.our_prefix().await;
    trace!(
        "{:?}, Sending msg to nodes: {:?}: {:?}",
        our_prefix,
        targets,
        msg
    );

    let name = network.our_name().await;
    let bytes = &msg.serialize()?;
    for target in targets {
        network
            .send_message(
                Itinerary {
                    src: SrcLocation::Node(name),
                    dst: DstLocation::Node(XorName(target.0)),
                    aggregation,
                },
                bytes.clone(),
            )
            .await
            .map_or_else(
                |err| {
                    error!("Unable to send Message to Peer: {:?}", err);
                },
                |()| {},
            );
    }
    Ok(())
}

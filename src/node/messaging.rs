// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node_ops::OutgoingMsg, Error};
use crate::{Network, Result};
use log::{error, trace};
use sn_messaging::{
    client::Message, client::ProcessMsg, Aggregation, DstLocation, Itinerary, SrcLocation,
};
use sn_routing::XorName;
use std::collections::BTreeSet;

pub(crate) async fn send(msg: OutgoingMsg, network: &Network) -> Result<()> {
    trace!("Sending msg: {:?}", msg);
    let src = if msg.section_source {
        SrcLocation::Section(network.our_prefix().await.name())
    } else {
        SrcLocation::Node(network.our_name().await)
    };
    let itinerary = Itinerary {
        src,
        dst: msg.dst,
        aggregation: msg.aggregation,
    };

    let target_section_pk = match msg.dst {
        DstLocation::EndUser(end_user) => Ok(end_user.id()),
        DstLocation::Section(name) | DstLocation::Node(name) => {
            network.get_section_pk_by_name(name).await?
        }
        Direct => Err(Error::CannotDirectMessage),
    }?;

    let message = Message::Process(msg.msg);
    let result = network
        .send_message(itinerary, message.serialize(msg.dst, target_section_pk)?)
        .await;

    result.map_or_else(
        |err| {
            error!("Unable to send msg: {:?}", err);
            Err(Error::Logic(format!("Unable to send msg: {:?}", msg.id())))
        },
        |()| Ok(()),
    )
}

pub(crate) async fn send_to_nodes(
    targets: BTreeSet<XorName>,
    msg: &ProcessMsg,
    network: &Network,
) -> Result<()> {
    trace!("Sending msg to nodes: {:?}: {:?}", targets, msg);

    let name = network.our_name().await;
    let message = Message::Process(msg);

    for target in targets {
        let target_section_pk = network.get_section_pk_by_name(target).await?;
        let message = Message::Process(msg.msg);
        let bytes = &message.serialize()?;

        network
            .send_message(
                Itinerary {
                    src: SrcLocation::Node(name),
                    dst: DstLocation::Node(XorName(target.0)),
                    aggregation: Aggregation::AtDestination,
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

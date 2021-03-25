// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node_ops::{OutgoingLazyError, OutgoingMsg},
    Error,
};
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

    let msg_id = msg.id();

    let dst_name = msg.dst.name().ok_or(Error::NoDestinationName)?;
    let target_section_pk = network.get_section_pk_by_name(&dst_name).await?;

    let target_section_pk = target_section_pk
        .bls()
        .ok_or(Error::NoSectionPublicKeyKnown(dst_name))?;

    let message = Message::Process(msg.msg);
    let result = network
        .send_message(itinerary, message.serialize(dst_name, target_section_pk)?)
        .await;

    result.map_or_else(
        |err| {
            error!("Unable to send msg: {:?}", err);
            Err(Error::UnableToSend(message))
        },
        |()| Ok(()),
    )
}

pub(crate) async fn send_error(msg: OutgoingLazyError, network: &Network) -> Result<()> {
    trace!("Sending msg: {:?}", msg);
    let src = SrcLocation::Node(network.our_name().await);
    let itinerary = Itinerary {
        src,
        dst: msg.dst,
        aggregation: Aggregation::AtDestination, // the odd error is irrelevant, accumulated however means it is what happened.
    };

    let msg_id = msg.id();

    let dst_name = msg.dst.name().ok_or(Error::NoDestinationName)?;
    let target_section_pk = network.get_section_pk_by_name(&dst_name).await?;

    let target_section_pk = target_section_pk
        .bls()
        .ok_or(Error::NoSectionPublicKeyKnown(dst_name))?;

    let message = Message::ProcessingError(msg.msg);
    let result = network
        .send_message(itinerary, message.serialize(dst_name, target_section_pk)?)
        .await;

    result.map_or_else(
        |err| {
            error!("Unable to send msg: {:?}", err);
            Err(Error::UnableToSend(message))
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
    let message = Message::Process(msg.clone());

    for target in targets {
        let target_section_pk = network
            .get_section_pk_by_name(&target)
            .await?
            .bls()
            .ok_or(Error::NoSectionPublicKeyKnown(target))?;
        let bytes = &message.serialize(target, target_section_pk)?;

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

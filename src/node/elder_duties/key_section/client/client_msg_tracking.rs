// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use super::client_input_parse::{try_deserialize_handshake, try_deserialize_msg};
pub use super::onboarding::Onboarding;
use crate::node::node_ops::MessagingDuty;
use log::{error, info, trace, warn};
use qp2p::SendStream;
use rand::{CryptoRng, Rng};
use sn_data_types::{Address, HandshakeRequest, Message, MessageId, MsgEnvelope, PublicKey};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};
use crate::utils;

/// Tracks incoming and outgoingg messages
/// between client and network.
pub struct ClientMsgTracking {
    onboarding: Onboarding,
    tracked_streams: HashMap<PublicKey, Vec<SendStream>>,
    tracked_incoming: HashMap<MessageId, (SocketAddr, SendStream)>,
    tracked_outgoing: HashMap<MessageId, MsgEnvelope>,
}


// TODO: On bootstrap / onboaring, we keep the stream. THIS IS THE ONE WE SEND EVENTS/CMDS ON.
// We can map a PK to a stream....
// We COULD have many of the same PKs attached.... Or many streams per PK, we send the event to _each known client_ as long as its there.
// Q: what to do as/when a connection is dropped.... Is that handled via qp2p magic?
// We'd have to map that.........
impl ClientMsgTracking {
    pub fn new(onboarding: Onboarding) -> Self {
        Self {
            onboarding,
            tracked_streams: Default::default(),
            tracked_incoming: Default::default(),
            tracked_outgoing: Default::default(),
        }
    }

    pub fn get_public_key(&mut self, peer_addr: SocketAddr) -> Option<&PublicKey> {
        self.onboarding.get_public_key(peer_addr)
    }

    pub fn process_handshake<G: CryptoRng + Rng>(
        &mut self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
        stream: SendStream,
        rng: &mut G,
    ) -> Option<MessagingDuty> {

        let mut the_stream = stream;
        let duty = self.onboarding.process(handshake, peer_addr, &mut the_stream, rng);


        // client has been onboarded or already exists
        if duty.is_none() {
            if let Some(pk) = self.get_public_key(peer_addr) {
                let mut updated_streams = vec!();
                let pk = pk.clone();

                // let's append to any existing known streams for this PK
                if let Some( current_streams_for_pk) = self.tracked_streams.remove(&pk) {
                    updated_streams = current_streams_for_pk;
                }
                
                updated_streams.push(the_stream);
                let _ = self.tracked_streams.insert(pk, updated_streams);
            }
            else{
                warn!("No PK found for onboarded peer at address : {:?}", peer_addr);
            }
        }

        duty

    }

    // pub fn remove_client(&mut self, peer_addr: SocketAddr) {
    //     self.onboarding.remove_client(peer_addr)
    // }

    ///
    /// // tODO: track incoming transaction validation requests against stream... ? Against socketsddr???
    pub fn track_incoming(
        &mut self,
        msg: &Message,
        client_address: SocketAddr,
        stream: SendStream,
    ) -> Option<MessagingDuty> {
        let msg_id = msg.id();
        // We could have received a group decision containing a client msg,
        // before receiving the msg from that client directly.
        if let Some(msg) = self.tracked_outgoing.remove(&msg_id) {
            warn!("Tracking incoming: Prior group decision on msg found.");

            // TODO: do we want to be avoiding this? 
            return Some(MessagingDuty::SendToClient {
                address: client_address,
                msg,
            });
        }


        // TODO: we don't always need to track incoming. CMDs should _not_ be tracked.

        if let Entry::Vacant(ve) = self.tracked_incoming.entry(msg_id) {
            let _ = ve.insert((client_address, stream));
            None
        } else {
            info!(
                "Pending MessageId {:?} reused - ignoring client message.",
                msg_id
            );
            None
        }
    }

    pub fn match_outgoing(&mut self, msg: &MsgEnvelope) -> Option<MessagingDuty> {
        match msg.destination() {
            Address::Client { .. } => (),
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid destination.",
                    self,
                    msg.id()
                );
                return None;
                //return Err(Error::InvalidOperation);
            }
        };
        let ( is_query_response, correlation_id) = match msg.message {
            Message::Event { correlation_id, .. }
            | Message::CmdError { correlation_id, .. } => (false, correlation_id),
            Message::QueryResponse { correlation_id, .. } => ( true, correlation_id ), 
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid message for client.",
                    self,
                    msg.id()
                );
                return None;
                //return Err(Error::InvalidOperation);
            }
        };

        warn!("!!!!!!!!!!!!!!OUTGOING MESSAGE W/ CORRELATION ID::: {:?}", correlation_id);
        // if is_query_response {
            trace!("Finding stream for QueryResponse");

            // Currently Query responses are sent on the stream from the connection. Events are sent to the held stream from the bootstrap process.
            
            match self.tracked_incoming.remove(&correlation_id) {
                Some((peer_addr, mut stream)) => {
                    if is_query_response {
                        send_message_on_stream(&msg, &mut stream)

                    }
                    else {
                        if let Some(pk) = self.get_public_key(peer_addr) {
                            let pk = pk.clone();
                            // get the streams and ownership
                            if let Some( streams) = self.tracked_streams.remove(&pk) {
                                let mut used_streams = vec!();
                                for mut stream in streams {
                                    // send to each registered stream for that PK
                                    send_message_on_stream(&msg, &mut stream);
                                    used_streams.push(stream);
                                    
                                }

                                let _ = self.tracked_streams.insert(pk, used_streams);
                            }
                            else {
                                error!("Could not find stream for Message response")
                            }
                        }
                        else {
                            error!("Could not find PublicKey for Message response")
                        }
                    }
                },
                // TODO: how do we know the client stream to send events on... any and all streams!?
                // IF CMDERror eg.... or EVENT
                // Hmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
                None => {
                    info!(
                        "{} for message-id {:?}, Unable to find client message to respond to. The message may have already been sent to the client.",
                        self, correlation_id
                    );
    
                    // let message = msg
    
                    let _ = self.tracked_outgoing.insert(correlation_id, msg.clone());
                    return None;
                    //return Err(Error::NoSuchKey);
                }
            }

            // if let Some(stream) = client_response_stream {

            //     send_message_on_stream(&msg, client_response_stream);
            // }
            // else {
            //     error!("Could not find stream for Message response")
            // }
        // }
        // else {
            
        // }


        None
        
        // Some(MessagingDuty::SendToClient {
        //     address: client_address,
        //     msg: msg.clone(),
        // })
    }


}

// TODO: asyncify
fn send_message_on_stream(message: &MsgEnvelope, stream: &mut SendStream) {

    warn!("Senging message on streammmmmmmmmmmmmmmmmmmmmmmm");
    let bytes = utils::serialise(message);
    // Hmmmm, what to do about this response.... we don't need a duty response here?
    let res = futures::executor::block_on(stream.send(bytes));

    match res {
        Ok(()) => info!("message sent to client!!!! via send stream"),
        Err(error) => error!("Some issue sendstreaming {:?}", error),
    };
}

impl Display for ClientMsgTracking {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientMsgTracking")
    }
}

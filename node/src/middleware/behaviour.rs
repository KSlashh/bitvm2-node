#![feature(trivial_bounds)]
use libp2p::identity::Keypair;
use libp2p::{
    gossipsub, kad,
    kad::{Mode, store::MemoryStore},
    mdns, noise,
    swarm::{StreamProtocol, SwarmEvent},
    tcp, yamux,
};
use libp2p_swarm_derive::NetworkBehaviour;
use std::error::Error;
use std::time::Duration;
use tokio::{
    io::{self, AsyncBufReadExt},
    select,
};
use tracing_subscriber::EnvFilter;

// We create a custom network behaviour that combines Kademlia and mDNS.
#[derive(NetworkBehaviour)]
pub struct AllBehaviours {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
}

impl AllBehaviours {
    pub fn new(key: &Keypair) -> Self {
        let mut cfg = kad::Config::new(IPFS_PROTO_NAME);
        cfg.set_query_timeout(Duration::from_secs(5 * 60));
        let store = kad::store::MemoryStore::new(key.public().to_peer_id());
        let kademlia = kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg);
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
            .unwrap();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(262144)
            .build()
            .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))
            .unwrap();
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
        )
        .expect("Valid configuration");
        Self { kademlia, mdns, gossipsub }
    }
}

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

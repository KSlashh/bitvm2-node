use crate::action::{
    GOATMessage, GOATMessageContent, handle_self_p2p_msg, recv_and_dispatch, send_to_peer,
};
use crate::env::get_local_node_info;
use crate::handle::{HandlerContext, handle_soldering_proof_payload_operator};
use crate::middleware::swarm::{BitvmSwarmWrapper, P2pMessageHandler, TickMessageType};
use crate::utils::{
    SolderingProofPullCoordinator, SolderingProofRangeRequest, SolderingProofRangeResponse,
    detect_heart_beat, read_soldering_proof_payload_range,
};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::BabeBundleBuilder;
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, request_response};
use std::sync::Arc;
use store::localdb::LocalDB;

pub struct BitvmNodeProcessor {
    pub local_db: LocalDB,
    pub btc_client: BTCClient,
    pub goat_client: GOATClient,
    pub http_client: HttpAsyncClient,
    pub soldering_builder: Option<Arc<BabeBundleBuilder>>,
    pub soldering_pulls: tokio::sync::Mutex<SolderingProofPullCoordinator>,
}
impl P2pMessageHandler for BitvmNodeProcessor {
    async fn recv_and_dispatch(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        actor: Actor,
        from_peer_id: PeerId,
        id: MessageId,
        message: &[u8],
    ) -> anyhow::Result<()> {
        recv_and_dispatch(
            swarm,
            &self.local_db,
            &self.btc_client,
            &self.goat_client,
            &self.http_client,
            &self.soldering_builder,
            actor,
            from_peer_id,
            id,
            message,
            Some(&self.soldering_pulls),
        )
        .await
    }

    async fn handle_tick_message(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        peer_id: PeerId,
        actor: Actor,
        msg_type: TickMessageType,
    ) -> anyhow::Result<()> {
        match msg_type {
            TickMessageType::HeartBeat => {
                match detect_heart_beat(swarm).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("detect_heart_beat: {e}");
                    }
                }
                tracing::debug!("Handling heartbeat tick message");
                Ok(())
            }
            TickMessageType::RegularlyAction => {
                tracing::debug!("Handling regular action tick message");
                let tick_data =
                    GOATMessage { actor: actor.clone(), content: GOATMessageContent::Tick }
                        .serialize_message()
                        .await?;

                handle_self_p2p_msg(
                    swarm,
                    &self.local_db,
                    &self.btc_client,
                    &self.goat_client,
                    &self.http_client,
                    &self.soldering_builder,
                    Some(&self.soldering_pulls),
                    actor,
                    peer_id,
                    GOATMessage::default_message_id(),
                    &tick_data,
                )
                .await
            }
        }
    }

    async fn finish_subscribe_topic(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        _actor: Actor,
        topic: &str,
    ) -> anyhow::Result<()> {
        if topic == Actor::All.to_string() {
            let message_content = GOATMessageContent::RequestNodeInfo(get_local_node_info());
            match send_to_peer(swarm, GOATMessage::new(Actor::All, message_content)).await {
                Ok(_) => {}
                Err(e) => {
                    println!("finish_subscribe_topic: send request NodeInfo {e}");
                }
            }
        }
        Ok(())
    }

    async fn handle_soldering_proof_range_request(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        peer_id: PeerId,
        request: SolderingProofRangeRequest,
        channel: request_response::ResponseChannel<SolderingProofRangeResponse>,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            ?peer_id,
            instance_id = %request.instance_id,
            graph_id = %request.graph_id,
            verifier_index = request.verifier_index,
            offset = request.offset,
            len = request.len,
            "handle soldering proof range request"
        );
        let response = read_soldering_proof_payload_range(&self.local_db, &request)?;
        swarm
            .behaviour_mut()
            .soldering_proof
            .send_response(channel, response)
            .map_err(|_| anyhow::anyhow!("send soldering proof range response failed"))?;
        Ok(())
    }

    async fn handle_soldering_proof_range_response(
        &self,
        swarm: &mut BitvmSwarmWrapper,
        actor: Actor,
        _local_peer_id: PeerId,
        peer_id: PeerId,
        request_id: request_response::OutboundRequestId,
        response: SolderingProofRangeResponse,
    ) -> anyhow::Result<()> {
        if actor != Actor::Operator {
            tracing::debug!("ignore soldering proof range response for non-operator actor {actor}");
            return Ok(());
        }
        let pulled = {
            let mut soldering_pulls = self.soldering_pulls.lock().await;
            soldering_pulls.handle_response(swarm, peer_id, request_id, response)?
        };
        let Some(pulled) = pulled else {
            return Ok(());
        };

        let mut ctx = HandlerContext {
            swarm,
            local_db: &self.local_db,
            btc_client: &self.btc_client,
            goat_client: &self.goat_client,
            http_client: &self.http_client,
            soldering_builder: &self.soldering_builder,
            actor,
            from_peer_id: peer_id,
            id: GOATMessage::default_message_id(),
            is_self_peer: get_local_node_info().peer_id == peer_id.to_string(),
            soldering_pulls: Some(&self.soldering_pulls),
        };
        handle_soldering_proof_payload_operator(
            &mut ctx,
            pulled.instance_id,
            pulled.graph_id,
            pulled.verifier_index,
            pulled.payload_hash,
            pulled.payload.len(),
            &pulled.payload,
        )
        .await
    }

    async fn handle_soldering_proof_range_failure(
        &self,
        request_id: request_response::OutboundRequestId,
        error: String,
    ) -> anyhow::Result<()> {
        let mut soldering_pulls = self.soldering_pulls.lock().await;
        soldering_pulls.handle_failure(request_id);
        tracing::error!(%request_id, error, "soldering proof range request failed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::action::{GOATMessage, GOATMessageContent, NodeInfo, send_to_peer};
    use crate::env::get_rpc_support_actors;
    use crate::middleware::swarm::{
        BitvmNetworkManager, BitvmSwarmConfig, BitvmSwarmWrapper, P2pMessageHandler,
        TickMessageType,
    };
    use crate::utils::{generate_local_key, save_node_info};
    use base64::Engine;
    use bitvm_lib::actors::Actor;
    use libp2p::PeerId;
    use libp2p::gossipsub::MessageId;
    use prometheus_client::registry::Registry;
    use store::localdb::LocalDB;
    use tokio_util::sync::CancellationToken;
    use tracing::Level;
    use tracing::warn;

    // Return (peer_key, peer_id)
    fn gen_local_key() -> anyhow::Result<(String, String)> {
        let local_key = generate_local_key();
        let base64_key =
            base64::engine::general_purpose::STANDARD.encode(&local_key.to_protobuf_encoding()?);
        Ok((base64_key, local_key.public().to_peer_id().to_string()))
    }

    fn generate_bootnode_url(peer_id: &str, port: u16) -> String {
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer_id}")
    }

    async fn create_and_run_bitvm_network_manager(
        local_key: Option<String>,
        p2p_port: u16,
        bootnodes: Vec<String>,
        actor: Actor,
        local_db: Option<LocalDB>,
        cancel_token: CancellationToken,
    ) {
        let mut metric_registry = Registry::default();
        let local_key = if let Some(local_key) = local_key {
            local_key
        } else {
            let (local_key, _) = gen_local_key().expect("get rand_p2p_key");
            local_key
        };
        let mut bitvm_network_manager = BitvmNetworkManager::new(
            BitvmSwarmConfig {
                local_key,
                p2p_port,
                bootnodes,
                topic_names: vec![
                    Actor::Committee.to_string(),
                    Actor::Verifier.to_string(),
                    Actor::Operator.to_string(),
                    Actor::Watchtower.to_string(),
                    Actor::All.to_string(),
                ],
                heartbeat_interval: 2,
                regular_task_interval: 3,
            },
            &mut metric_registry,
        )
        .expect("create bitvm swarm");

        let local_db = if let Some(local_db) = local_db {
            local_db
        } else {
            store::create_local_db(&temp_sqlite_db_path()).await
        };
        bitvm_network_manager
            .run(actor, MockBitvmNodeProcessor { local_db }, cancel_token)
            .await
            .expect("Failed to run bitvm swarm");
    }

    #[derive(Debug)]
    struct MockBitvmNodeProcessor {
        pub local_db: LocalDB,
    }
    pub async fn detect_heart_beat(
        swarm: &mut BitvmSwarmWrapper,
        node_info: NodeInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("start detect_heart_beat");
        let message_content = GOATMessageContent::RequestNodeInfo(node_info);
        // send to actor
        let actors = get_rpc_support_actors();
        for actor in actors {
            match send_to_peer(swarm, GOATMessage::new(actor, message_content.clone())).await {
                Ok(_) => {}
                Err(err) => warn!("{err}"),
            }
        }
        Ok(())
    }
    impl P2pMessageHandler for MockBitvmNodeProcessor {
        #[tracing::instrument(level = Level::INFO)]
        async fn recv_and_dispatch(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            actor: Actor,
            from_peer_id: PeerId,
            id: MessageId,
            message: &[u8],
        ) -> anyhow::Result<()> {
            if id == GOATMessage::default_message_id() {
                tracing::info!("recv_and_dispatch receive local message");
                return Ok(());
            }
            let message = GOATMessage::deserialize_message(message).await?;
            let content: &GOATMessageContent = message.content();
            if let (GOATMessageContent::RequestNodeInfo(node_info), _) = (content, actor) {
                save_node_info(&self.local_db, node_info).await.expect("save_node_info");
            }
            Ok(())
        }

        #[tracing::instrument(level = Level::INFO)]
        async fn handle_tick_message(
            &self,
            swarm: &mut BitvmSwarmWrapper,
            _peer_id: PeerId,
            actor: Actor,
            msg_type: TickMessageType,
        ) -> anyhow::Result<()> {
            match msg_type {
                TickMessageType::HeartBeat => {
                    detect_heart_beat(
                        swarm,
                        NodeInfo {
                            peer_id: "test".to_string(),
                            actor: actor.to_string(),
                            goat_addr: "test".to_string(),
                            btc_pub_key: "btc_pub_key_test".to_string(),
                            socket_addr: "test".to_string(),
                            node_name: "".to_string(),
                            service_fee_rate: 0.0,
                            available_peg_btc: "0".to_string(),
                        },
                    )
                    .await
                    .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                    Ok(())
                }
                TickMessageType::RegularlyAction => Ok(()),
            }
        }

        #[tracing::instrument(level = Level::INFO)]
        async fn finish_subscribe_topic(
            &self,
            _swarm: &mut BitvmSwarmWrapper,
            actor: Actor,
            topic: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn init() {
        let _ = tracing_subscriber::fmt().try_init();
    }

    fn temp_sqlite_db_path() -> String {
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        format!("sqlite:{}", tmp_db.path().as_os_str().to_str().unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn test_p2p_heart_beat() -> anyhow::Result<()> {
        init();
        let local_db = store::create_local_db(&temp_sqlite_db_path()).await;
        let local_db_clone = local_db.clone();
        let cancellation_token = CancellationToken::new();
        let cancel_token_clone = cancellation_token.clone();
        let (local_key, peer_id) = gen_local_key()?;
        let bootnode_url = generate_bootnode_url(&peer_id, 9100);
        tokio::spawn(create_and_run_bitvm_network_manager(
            Some(local_key),
            9100,
            vec![],
            Actor::Committee,
            Some(local_db),
            cancel_token_clone,
        ));
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let cancel_token_clone = cancellation_token.clone();
        tokio::spawn(create_and_run_bitvm_network_manager(
            None,
            9101,
            vec![bootnode_url],
            Actor::Operator,
            None,
            cancel_token_clone,
        ));

        let mut index = 1;
        let mut success = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if index == 10 {
                break;
            }

            let mut storage_processor =
                local_db_clone.acquire().await.expect("Failed to acquire local db processor");
            if let Some(node) = storage_processor
                .get_node_by_btc_pub_key("btc_pub_key_test")
                .await
                .expect("Failed to get btc_pub_key")
            {
                success = node.actor == Actor::Operator.to_string();
                break;
            }
            index += 1;
        }
        cancellation_token.cancel();
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(success);
        Ok(())
    }
}

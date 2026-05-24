use crate::action::{
    AssertReady, ChallengeSent, DisproveSent, GOATMessageContent, KickoffReady, KickoffSent,
    PreKickoffSent, Take1Ready, Take1Sent, Take2Ready, Take2Sent, WronglyChallengeTimeout,
};
use crate::env::get_network;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::fetch_on_turn_graph_by_status;
use crate::utils::todo_funcs::min_required_watchtower;
use crate::utils::{SELF_SENDER, outpoint_spent_txid, upsert_message};
use bitcoin::Txid;
use bitvm_lib::actors::Actor;
use bitvm_lib::operator::{take1_timelock, take2_timelock};
use bitvm_lib::verifier::disprove_timelock;
use client::btc_chain::BTCClient;
use client::goat_chain::DisproveTxType;
use serde::{Deserialize, Serialize};
use store::localdb::{LocalDB, StorageProcessor};
use store::{
    GoatTxProcessingStatus, GoatTxType, Graph, GraphBtcTxVoutMonitor, GraphStatus, SerializableTxid,
};
use strum::{Display, EnumString};
use tracing::{info, trace, warn};
use uuid::Uuid;

// const CONNECTOR_D_MARGIN: u64 = 2;
const CONNECTOR_GUARDIAN_MARGIN: u64 = 2;

const MONITE_BTC_TX_NAME_KICKOFF: &str = "kickoff";
const MONITE_BTC_TX_NAME_WATCHTOWER_INIT: &str = "watchtower_init";
const MONITE_BTC_TX_NAME_PROVER_ASSERT: &str = "prover_assert";

fn get_take1_timelock_config() -> i64 {
    take1_timelock(get_network()) as i64
}

fn get_take2_timelock_config() -> i64 {
    take2_timelock(get_network()) as i64
}

fn get_disprove_timelock_config() -> i64 {
    disprove_timelock(get_network()) as i64
}
#[derive(Clone, Debug, Eq, PartialEq, Display, EnumString)]
enum OperatorWithdrawType {
    Take1,
    Take2,
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq, Display, EnumString,
)]
pub enum VerifierChallengeStatus {
    #[default]
    None,
    VerifierAsserted,
    ProverAnswered,
    Disproved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ChallengeSubStatus {
    pub watchtower_challenge_status: Vec<bool>, // true for challenge connector spend
    pub verifier_challenge_status: Vec<VerifierChallengeStatus>,
    pub disprove_type: Option<DisproveTxType>,
    pub disprove_index: i32,
}

impl ChallengeSubStatus {
    pub fn is_watchtower_challenge_success(&self, required_watchtower_num: usize) -> bool {
        self.watchtower_challenge_status
            .iter()
            .filter(|&&status| status)
            .take(required_watchtower_num)
            .count()
            == required_watchtower_num
    }

    pub fn is_disproved(&self) -> bool {
        self.disprove_type.is_some()
    }
}

pub async fn get_user_init_withdraw_graphs<'a>(
    storage_processor: &mut StorageProcessor<'a>,
) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
    let goat_tx_records = storage_processor
        .get_goat_tx_record_by_processing_status(
            &GoatTxType::InitWithdraw.to_string(),
            &GoatTxProcessingStatus::Pending.to_string(),
        )
        .await?;
    Ok(goat_tx_records.iter().map(|v| (v.instance_id, v.graph_id)).collect())
}

/// may trigger: KickoffReady
pub async fn detect_init_withdraw_call(local_db: &LocalDB) -> anyhow::Result<()> {
    trace!("start tick action: detect_init_withdraw_call");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        get_user_init_withdraw_graphs(&mut storage_processor).await?
    };
    info!("start tick action: detect_init_withdraw_call get graphs:{}", graphs.len());
    for (instance_id, graph_id) in graphs {
        let mut tx = local_db.start_transaction().await?;
        if let Ok(Some(graph)) = tx.find_graph(&graph_id).await {
            if graph.instance_id.ne(&instance_id) {
                warn!(
                    "Graph:{graph_id} recorded instance_id:{} not equal expected instance_id:{instance_id}",
                    graph.instance_id
                );
                continue;
            }
            upsert_message(
                &mut tx,
                false,
                graph_id,
                None,
                SELF_SENDER.to_string(),
                Actor::Operator,
                GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
                0,
                0,
            )
            .await?;
        } else {
            warn!(
                "instance_id: {instance_id} graph_id: {graph_id} fail to get graph from db or kickoff txid is none"
            );
        }
        tx.update_goat_tx_record_processing_status(
            &graph_id,
            &instance_id,
            &GoatTxType::InitWithdraw.to_string(),
            &GoatTxProcessingStatus::Processed.to_string(),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// may trigger: KickoffSent
pub async fn detect_kickoff(local_db: &LocalDB, btc_client: &BTCClient) -> anyhow::Result<()> {
    trace!("start tick action: detect_kickoff");
    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_on_turn_graph_by_status(
            &mut storage_processor,
            &GraphStatus::OperatorDataPushed.to_string(),
        )
        .await?
    };
    info!("start tick action: detect_kickoff, graphs: {}", graphs.len());
    for graph in graphs {
        let kickoff_txid: Txid = match graph.kickoff_txid.clone() {
            Some(kickoff_txid) => kickoff_txid.into(),
            _ => {
                warn!("graph_id {}, kickoff txid or next_pre_kickoff is none", graph.graph_id);
                continue;
            }
        };

        if let Ok(tx_status) = btc_client.get_tx_status(&kickoff_txid).await
            && tx_status.confirmed
        {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                SELF_SENDER.to_string(),
                Actor::All,
                GOATMessageContent::KickoffSent(KickoffSent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
                0,
                0,
            )
            .await?;
        } else {
            warn!("graph_id:{} kickoff:{kickoff_txid:?} is not onchain", graph.graph_id);
            continue;
        }
    }
    Ok(())
}

/// may trigger: Take1Ready, Take1Sent, ChallengeSent
pub async fn detect_take1_or_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    trace!("start tick action: detect_take1_or_challenge");

    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_on_turn_graph_by_status(
            &mut storage_processor,
            &GraphStatus::OperatorKickOff.to_string(),
        )
        .await?
    };
    let current_height = btc_client.get_height().await? as i64;
    info!(
        "start tick action: detect_take1_or_challenge, graphs: {}, current_height: {current_height}",
        graphs.len()
    );
    let lock_blocks = get_take1_timelock_config();
    for graph in graphs {
        if detect_kickoff_ref_disprove_tx(btc_client, local_db, &graph).await? {
            warn!(
                "process_graph_challenge detect_kickoff_ref_disprove_tx happened at graph:{}",
                graph.graph_id
            );
            continue;
        }
        // process_kickoff_graph may trigger Take1Ready, Take1Sent or ChallengeSent
        if let Some((actor, message_content)) =
            process_kickoff_graph(btc_client, local_db, &graph, lock_blocks, current_height).await?
        {
            info!("process_kickoff_graph detect take1 ready or take1 sent or challenge sent");
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                SELF_SENDER.to_string(),
                actor,
                message_content,
                0,
                0,
            )
            .await?;
        }
    }
    Ok(())
}

/// TBD: Currently, the challenge flow is driven by P2P messages; it should be changed to monitoring-driven in the future.
#[tracing::instrument(level = "info", skip(local_db, btc_client))]
pub async fn process_graph_challenge(
    local_db: &LocalDB,
    btc_client: &BTCClient,
) -> anyhow::Result<()> {
    trace!("start tick action: process_graph_challenge");

    let graphs = {
        let mut storage_processor = local_db.acquire().await?;
        fetch_on_turn_graph_by_status(&mut storage_processor, &GraphStatus::Challenge.to_string())
            .await?
    };
    let current_height = btc_client.get_height().await? as i64;
    info!(
        "start tick action: process_graph_challenge, graphs: {}, current_height: {current_height}",
        graphs.len()
    );

    for graph in graphs {
        if let Some((actor, message_content)) =
            detect_watchtower_challenge(btc_client, local_db, &graph).await?
        {
            info!("process_graph_challenge detect enough watchtower challenges");
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                SELF_SENDER.to_string(),
                actor,
                message_content,
                0,
                0,
            )
            .await?;
        }

        if let Some((actor, message_content, sub_type)) =
            detect_assert_disprove_ready(btc_client, local_db, &graph, current_height).await?
        {
            info!("process_graph_challenge detect assert disprove ready");
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                sub_type,
                SELF_SENDER.to_string(),
                actor,
                message_content,
                0,
                0,
            )
            .await?;
        }

        // take2 monitor
        if let Some((actor, message_content)) =
            detect_take2(btc_client, local_db, &graph, current_height).await?
        {
            info!("process_graph_challenge detect take2 ready or take2 sent or disprove sent");
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph.graph_id,
                None,
                SELF_SENDER.to_string(),
                actor,
                message_content,
                0,
                0,
            )
            .await?;
        }
    }
    Ok(())
}

/// may trigger: AssertReady
async fn detect_watchtower_challenge(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    let watchtower_challenge_init_txid: Txid = match graph.watchtower_challenge_init_txid.clone() {
        Some(txid) => txid.into(),
        None => {
            warn!(
                "detect_watchtower_challenge graph_id:{} watchtower_challenge_init_txid is none",
                graph.graph_id
            );
            return Ok(None);
        }
    };
    let required_watchtower_num = min_required_watchtower();

    let monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(
                &graph.graph_id,
                &SerializableTxid::from(watchtower_challenge_init_txid),
            )
            .await?
    };
    let (_height, vout_len) = match monitor {
        Some(monitor) if monitor.height > 0 && monitor.vout_len > 0 => {
            (monitor.height, monitor.vout_len)
        }
        monitor => {
            let Some(tx_info) = btc_client.get_tx_info(&watchtower_challenge_init_txid).await?
            else {
                trace!(
                    "detect_watchtower_challenge graph_id:{} watchtower challenge init txid {} not on chain",
                    graph.graph_id, watchtower_challenge_init_txid
                );
                return Ok(None);
            };
            let height = tx_info.status.block_height.unwrap_or_default() as i64;
            if height <= 0 {
                trace!(
                    "detect_watchtower_challenge graph_id:{} watchtower challenge init txid {} not confirmed",
                    graph.graph_id, watchtower_challenge_init_txid
                );
                return Ok(None);
            }

            let current_times = current_time_secs();
            let (monitor_data, created_at, tx_name) = match monitor {
                Some(monitor) => (monitor.monitor_data, monitor.created_at, monitor.tx_name),
                None => {
                    (String::new(), current_times, MONITE_BTC_TX_NAME_WATCHTOWER_INIT.to_string())
                }
            };
            let vout_len = tx_info.vout.len() as i64;
            let mut storage_processor = local_db.acquire().await?;
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    tx_name,
                    txid: SerializableTxid::from(watchtower_challenge_init_txid),
                    height,
                    vout_len,
                    monitor_data,
                    created_at,
                    updated_at: current_times,
                })
                .await?;
            (height, vout_len)
        }
    };

    let mut spent_challenge_connector_num = 0;
    for vout in 0..vout_len as u64 {
        if outpoint_spent_txid(btc_client, &watchtower_challenge_init_txid, vout).await?.is_some() {
            spent_challenge_connector_num += 1;
            if spent_challenge_connector_num >= required_watchtower_num {
                return Ok(Some((
                    Actor::Operator,
                    GOATMessageContent::AssertReady(AssertReady {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                )));
            }
        }
    }
    Ok(None)
}

// may trigger disprove ready
async fn detect_assert_disprove_ready(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent, Option<String>)>> {
    let operator_assert_txid = match graph.operator_assert_txid.clone() {
        Some(operator_assert_txid) => operator_assert_txid.into(),
        None => {
            warn!(
                "detect_assert_disprove_ready graph_id:{} operator_assert_txid has none value",
                graph.graph_id
            );
            return Ok(None);
        }
    };
    if graph.verifier_assert_txids.is_empty() {
        return Ok(None);
    }

    let connector_d_vout = graph.verifier_assert_txids.len() as u64;
    if outpoint_spent_txid(btc_client, &operator_assert_txid, connector_d_vout).await?.is_some() {
        trace!(
            "detect_assert_disprove_ready graph_id:{} connector_d already spent",
            graph.graph_id
        );
        return Ok(None);
    }

    for (index, verifier_assert_txid) in graph.verifier_assert_txids.iter().enumerate() {
        let verifier_assert_txid: Txid = verifier_assert_txid.clone().into();
        if outpoint_spent_txid(btc_client, &verifier_assert_txid, 0).await?.is_some() {
            continue;
        }

        let height = {
            let mut storage_processor = local_db.acquire().await?;
            storage_processor
                .find_graph_btc_tx_vout_monitor(&graph.graph_id, &verifier_assert_txid.into())
                .await?
                .unwrap_or_default()
                .height
        };
        let height = if height <= 0 {
            let Some(tx_info) = btc_client.get_tx_info(&verifier_assert_txid).await? else {
                continue;
            };
            let height = tx_info.status.block_height.unwrap_or_default() as i64;
            if height <= 0 {
                continue;
            }

            let current_times = current_time_secs();
            let mut storage_processor = local_db.acquire().await?;
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id: graph.graph_id,
                    tx_name: format!("verifier_assert_{index}"),
                    txid: verifier_assert_txid.into(),
                    height,
                    vout_len: tx_info.vout.len() as i64,
                    monitor_data: String::new(),
                    created_at: current_times,
                    updated_at: current_times,
                })
                .await?;
            height
        } else {
            height
        };

        if height + get_disprove_timelock_config() <= current_height {
            info!(
                "detect_assert_disprove_ready graph_id:{} verifier_assert index:{} is ready to disprove",
                graph.graph_id, index
            );
            return Ok(Some((
                Actor::Verifier,
                GOATMessageContent::WronglyChallengeTimeout(WronglyChallengeTimeout {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                    challenge_assert_txid: verifier_assert_txid,
                }),
                Some(index.to_string()),
            )));
        }
    }

    Ok(None)
}

/// Check if Take1Ready Take2Ready message needs to be sent
async fn check_operator_withdraw_ready_condition(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph_id: Uuid,
    check_tx_items: Vec<(Txid, String, OperatorWithdrawType, i64, i64)>, // (txid, tag,  height, lock_blocks)
    current_height: i64,
) -> anyhow::Result<bool> {
    info!(
        "check_operator_withdraw_ready_condition for graph_id: {graph_id}, check tx size: {}, detail:{check_tx_items:?}",
        check_tx_items.len()
    );
    let mut ready = true;
    for (txid, tx_name, operator_withdraw_type, height, lock_blocks) in check_tx_items {
        let height = if height <= 0 {
            let current_times = current_time_secs();
            let (height, vout_len) = match btc_client.get_tx_info(&txid).await? {
                Some(tx_info) => (
                    tx_info.status.block_height.unwrap_or_default() as i64,
                    tx_info.vout.len() as i64,
                ),
                None => {
                    info!("graph_id:{graph_id}, {operator_withdraw_type} txid {txid} not on chain",);
                    return Ok(false);
                }
            };
            let txid_serial: SerializableTxid = txid.into();
            let mut storage_processor = local_db.acquire().await?;
            let existing =
                storage_processor.find_graph_btc_tx_vout_monitor(&graph_id, &txid_serial).await?;
            let (monitor_data, created_at, tx_name_to_use) = match existing {
                Some(existing) => (existing.monitor_data, existing.created_at, existing.tx_name),
                None => ("".to_string(), current_times, tx_name.clone()),
            };
            storage_processor
                .upsert_graph_btc_tx_vout_monitor(&GraphBtcTxVoutMonitor {
                    graph_id,
                    tx_name: tx_name_to_use,
                    txid: txid_serial,
                    height,
                    vout_len,
                    monitor_data,
                    created_at,
                    updated_at: current_times,
                })
                .await?;
            height
        } else {
            height
        };

        info!(
            "graph_id:{graph_id}, {operator_withdraw_type} txid {txid}  at height {height} lock_blocks {lock_blocks}, current height: {current_height}  ",
        );

        if height == 0 || height > 0 && height + lock_blocks > current_height {
            ready = false;
            break;
        }
    }
    Ok(ready)
}

/// Process graph data in KickOff status
/// may return: Take1Ready, Take1Sent, ChallengeSent
async fn process_kickoff_graph(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    lock_blocks: i64,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    trace!("process_kickoff_graph: {}", graph.graph_id);
    let (kickoff_txid, take1_txid) = match (graph.kickoff_txid.clone(), graph.take1_txid.clone()) {
        (Some(kickoff), Some(take1)) => (kickoff.into(), take1.into()),
        _ => {
            // NOTE: revert to previous status?
            warn!("process_kickoff_graph graph_id:{}, kickoff or take1 is none", graph.graph_id);
            return Ok(None);
        }
    };
    let spent_txid = match outpoint_spent_txid(btc_client, &kickoff_txid, 0).await? {
        Some(txid) => txid,
        None => {
            // kickoff output not spent, check if we need to send Take1Ready
            let height = {
                let mut storage_processor = local_db.acquire().await?;
                storage_processor
                    .find_graph_btc_tx_vout_monitor(&graph.graph_id, &kickoff_txid.into())
                    .await?
                    .unwrap_or_default()
                    .height
            };
            if check_operator_withdraw_ready_condition(
                btc_client,
                local_db,
                graph.graph_id,
                vec![(
                    kickoff_txid,
                    MONITE_BTC_TX_NAME_KICKOFF.to_string(),
                    OperatorWithdrawType::Take1,
                    height,
                    lock_blocks,
                )],
                current_height,
            )
            .await?
            {
                info!(
                    "process_kickoff_graph graph_id:{}, take1 is ready to send to btc chain",
                    graph.graph_id
                );
                return Ok(Some((
                    Actor::Operator,
                    GOATMessageContent::Take1Ready(Take1Ready {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                    }),
                )));
            } else {
                trace!("process_kickoff_graph graph_id:{}, take1 not ready", graph.graph_id);
            }
            return Ok(None);
        }
    };
    if spent_txid == take1_txid {
        info!(
            "process_kickoff_graph graph_id:{}, take1 is on chain, will try call contract",
            graph.graph_id
        );
        Ok(Some((
            Actor::Committee,
            GOATMessageContent::Take1Sent(Take1Sent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        info!(
            "process_kickoff_graph graph_id:{}, challenge txid: {} has been detected.",
            graph.graph_id,
            spent_txid.to_string()
        );
        // Challenge was sent
        Ok(Some((
            Actor::Operator,
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                challenge_txid: spent_txid,
            }),
        )))
    }
}

/// may trigger: DisproveSent(QuickChallenge/ChallengeIncompleteKickoff)
async fn detect_kickoff_ref_disprove_tx(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
) -> anyhow::Result<bool> {
    let mut detected = false;
    let (kickoff_txid, take1_txid, take2_txid, next_pre_kickoff): (
        Txid,
        Txid,
        Txid,
        SerializableTxid,
    ) = match (
        graph.kickoff_txid.clone(),
        graph.take1_txid.clone(),
        graph.take2_txid.clone(),
        graph.next_prekickoff.clone(),
    ) {
        (Some(kickoff_txid), Some(take1_txid), Some(take2_txid), Some(next_pre_kickoff)) => {
            (kickoff_txid.into(), take1_txid.into(), take2_txid.into(), next_pre_kickoff)
        }
        _ => {
            warn!("graph:{} kickoff_txid/take1_txid/take2_txid  has none value", graph.graph_id);
            return Ok(detected);
        }
    };
    let pre_sents = check_pre_kickoff_sent(local_db, btc_client, next_pre_kickoff, 2).await?;
    if pre_sents > 0 {
        info!("graph_id:{} next {pre_sents} graphs's pre_kickoff has been sent!", graph.graph_id);
        detected = true;
    }
    let out_monitor = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &kickoff_txid.into())
            .await?
    };

    let Some(out_monitor) = out_monitor else {
        return Ok(false);
    };

    if let Some(spend_txid) = outpoint_spent_txid(
        btc_client,
        &kickoff_txid,
        out_monitor.vout_len as u64 - CONNECTOR_GUARDIAN_MARGIN,
    )
    .await?
        && let Some(tx) = btc_client.get_tx(&spend_txid).await?
    {
        if spend_txid == take1_txid || spend_txid == take2_txid || tx.input.len() < 2 {
            return Ok(false);
        }

        let disprove_type = if tx.input[1].previous_output.vout == 0 {
            DisproveTxType::QuickChallenge
        } else {
            DisproveTxType::ChallengeIncompleteKickoff
        };

        info!(
            "graph_id:{} is disproved, spent txid:{}, disprove_type:{}",
            graph.graph_id, spend_txid, disprove_type
        );
        let challenge_start_txid: Option<Txid> = graph.challenge_txid.clone().map(|v| v.into());
        let mut storage_processor = local_db.acquire().await?;
        upsert_message(
            &mut storage_processor,
            false,
            graph.graph_id,
            None,
            SELF_SENDER.to_string(),
            Actor::Committee,
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
                disprove_type,
                index: 0,
                challenge_start_txid,
                challenge_finish_txid: spend_txid,
            }),
            0,
            0,
        )
        .await?;
        detected = true;
    }
    Ok(detected)
}

/// may trigger: Take2Ready, Take2Sent, DisproveSent(Disprove)
async fn detect_take2(
    btc_client: &BTCClient,
    local_db: &LocalDB,
    graph: &Graph,
    current_height: i64,
) -> anyhow::Result<Option<(Actor, GOATMessageContent)>> {
    let (kickoff_txid, operator_assert_txid, take2_txid) = match (
        graph.kickoff_txid.clone(),
        graph.operator_assert_txid.clone(),
        graph.take2_txid.clone(),
    ) {
        (Some(kickoff_txid), Some(operator_assert_txid), Some(take2_txid)) => {
            (kickoff_txid.into(), operator_assert_txid.into(), take2_txid.into())
        }
        _ => {
            warn!(
                "detect_take2 graph_id:{} kickoff_txid/operator_assert_txid/take2_txid has none value",
                graph.graph_id
            );
            return Ok(None);
        }
    };

    let connector_d_vout = graph.verifier_assert_txids.len() as u64;
    if let Some(spend_txid) =
        outpoint_spent_txid(btc_client, &operator_assert_txid, connector_d_vout).await?
    {
        if spend_txid == take2_txid {
            info!("detect_take2 graph_id:{} take2 is on chain", graph.graph_id);
            return Ok(Some((
                Actor::Committee,
                GOATMessageContent::Take2Sent(Take2Sent {
                    instance_id: graph.instance_id,
                    graph_id: graph.graph_id,
                }),
            )));
        }

        if let Some(tx) = btc_client.get_tx(&spend_txid).await?
            && tx.input.len() == 2
        {
            let verifier_assert_txid = tx.input[0].previous_output.txid;
            if let Some(index) = graph
                .verifier_assert_txids
                .iter()
                .position(|txid| Txid::from(txid.clone()) == verifier_assert_txid)
            {
                info!(
                    "detect_take2 graph_id:{} disprove is on chain, spent txid:{}, index:{}",
                    graph.graph_id, spend_txid, index
                );
                return Ok(Some((
                    Actor::Committee,
                    GOATMessageContent::DisproveSent(DisproveSent {
                        instance_id: graph.instance_id,
                        graph_id: graph.graph_id,
                        disprove_type: DisproveTxType::Disprove,
                        index,
                        challenge_start_txid: graph.challenge_txid.clone().map(|v| v.into()),
                        challenge_finish_txid: spend_txid,
                    }),
                )));
            }
        }

        warn!(
            "detect_take2 graph_id:{} connector_d spent by unknown txid:{}",
            graph.graph_id, spend_txid
        );
        return Ok(None);
    }

    let guardian_connector_vout = 3;
    if outpoint_spent_txid(btc_client, &kickoff_txid, guardian_connector_vout).await?.is_some() {
        trace!("detect_take2 graph_id:{} guardian connector already spent", graph.graph_id);
        return Ok(None);
    }

    let height = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_btc_tx_vout_monitor(&graph.graph_id, &operator_assert_txid.into())
            .await?
            .unwrap_or_default()
            .height
    };
    if check_operator_withdraw_ready_condition(
        btc_client,
        local_db,
        graph.graph_id,
        vec![(
            operator_assert_txid,
            MONITE_BTC_TX_NAME_PROVER_ASSERT.to_string(),
            OperatorWithdrawType::Take2,
            height,
            get_take2_timelock_config(),
        )],
        current_height,
    )
    .await?
    {
        info!("detect_take2 graph_id:{} take2 is ready to send to btc chain", graph.graph_id);
        Ok(Some((
            Actor::Operator,
            GOATMessageContent::Take2Ready(Take2Ready {
                instance_id: graph.instance_id,
                graph_id: graph.graph_id,
            }),
        )))
    } else {
        trace!("detect_take2 graph_id:{} take2 not ready", graph.graph_id);
        Ok(None)
    }
}

/// may trigger: PreKickoffSent
async fn check_pre_kickoff_sent(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    pre_kickoff: SerializableTxid,
    check_level: i32,
) -> anyhow::Result<usize> {
    let check_graphs = {
        let mut check_graphs: Vec<(Uuid, Uuid, Txid)> = vec![];
        let mut storage_processor = local_db.acquire().await?;
        let mut check_level = check_level;
        let mut pre_kickoff = pre_kickoff;

        while check_level > 0 {
            if let Some((graph_id, instance_id, cur_pre_kickoff, next_pre_kickoff)) =
                storage_processor
                    .get_graph_pre_kickoff_chain_by_cur_pre_kickoff(pre_kickoff.clone())
                    .await?
            {
                check_graphs.push((graph_id, instance_id, cur_pre_kickoff.into()));
                pre_kickoff = next_pre_kickoff;
                check_level -= 1;
            } else {
                break;
            }
        }
        check_graphs
    };
    let mut pre_sents = 0;
    for (graph_id, instance_id, cur_pre_kickoff) in check_graphs {
        if btc_client.get_tx_status(&cur_pre_kickoff).await?.confirmed {
            let mut storage_processor = local_db.acquire().await?;
            upsert_message(
                &mut storage_processor,
                false,
                graph_id,
                None,
                SELF_SENDER.to_string(),
                Actor::Verifier,
                GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
                0,
                0,
            )
            .await?;
            pre_sents += 1;
        }
    }
    Ok(pre_sents)
}

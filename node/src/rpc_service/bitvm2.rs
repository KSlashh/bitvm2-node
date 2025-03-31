use std::collections::HashMap;
use axum::extract::State;
use axum::{Json, Router, http::StatusCode};
use bitvm2_lib::actors::Actor;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use store::localdb::LocalDB;
use store::{Instance, Graph, GraphStatus, BridgeInStatus, BridgeOutStatus};
use tracing_subscriber::fmt::time;
use crate::rpc_service::current_time_secs;

// the input to our `create_user` handler
#[axum::debug_handler]
pub async fn create_instance(
    State(local_db): State<Arc<LocalDB>>,
    Json(payload): Json<BridgeInTransactionPrepare>,
) -> (StatusCode, Json<BridgeInTransactionPrepareResponse>) {
    // insert your application logic here
    let tx = Instance {
        instance_id: payload.instance_id,
        bridge_path: payload.bridge_path,
        from: payload.from,
        to: payload.to,
        // in sat
        amount: payload.amount,
        created_at: current_time_secs(),

        // updating time
        eta_at: current_time_secs(),

        // BridgeInStatus | BridgeOutStutus
        status: BridgeInStatus::Submitted.to_string(),

        ..Default::default()
        //pub goat_txid: String,
        //pub btc_txid: String,
    };

    local_db.create_instance(tx.clone()).await;

    let resp = BridgeInTransactionPrepareResponse{};
    (StatusCode::OK, Json(resp))
}
#[derive(Deserialize, Serialize)]
pub struct UTXO {
    txid: String,
    vout: u32,
    //.. others
}

/// bridge-in: step1 & step2.1
#[derive(Deserialize)]
pub struct BridgeInTransactionPrepare {
    /// UUID
    pub instance_id: String,
    /// testnet3 | mainnet
    pub network: String,
    /// pBTC <-> tBTC | BTC
    pub bridge_path: String,
    pub amount: u64,
    pub fee_rate: u64,
    pub utxo: Vec<UTXO>,

    // address
    pub from: String,
    pub to: String,
}

#[derive(Deserialize, Serialize)]
pub struct BridgeInTransactionPrepareResponse {
}

/// bridge-in step2.2

/// deps: BridgeInTransactionPrepare
///  handler: operator
///     Operator creates a graph record in database and broadcast the new graph to peers
#[derive(Deserialize)]
pub struct GraphGenerate {
    pub instance_id: String,
    // UUID
    pub graph_id: String,

    //calculate staking amount according to the peg-in amount
}

// UI can go next(step2.3) once one operator responds
#[derive(Deserialize, Serialize)]
pub struct GraphGenerateResponse {
    pub instance_id: String,
    pub graph_id: String,
    // unsigned_txns, operator signature, this steps ask operator to publish unsigned txns
    pub graph_ipfs_unsigned_txns: String,
    pub graph_ipfs_operator_sig: String,
}

/// bridge-in step 2.3

/// handler: committee
#[derive(Deserialize)]
pub struct GraphPresign {
    pub instance_id: String,
    pub graph_id: String,
    // the root directory of all graph_ipfs_* files
    pub graph_ipfs_base_url: String,
}

// Committee publishs txn signatures in ipfs url
#[derive(Deserialize, Serialize)]
pub struct GraphPresignResponse {
    pub instance_id: String,
    pub graph_id: String,
    pub graph_ipfs_committee_sig: String,
}

#[derive(Deserialize)]
pub struct GraphPresignCheck {
    pub instance_id: String,
    // get graph_id from nodes' database,
}

#[derive(Deserialize, Serialize)]
pub struct GraphPresignCheckResponse {
    pub instance_id: String,
    pub instace_status: BridgeInStatus,
    pub graph_status: HashMap<String, GraphStatus>,
    pub tx: Option<Instance>,
}

/// bridge-in: step3

/// handler: relayer
#[derive(Deserialize)]
pub struct PegBTCMint {
    pub instance_id: String,
    pub graph_id: Vec<String>,
    pub pegin_txid: String,
    // TODO: https://github.com/GOATNetwork/bitvm2-L2-contracts/blob/main/contracts/Gateway.sol#L43
}

#[derive(Deserialize, Serialize)]
pub struct PegBTCMintResponse {
    // 200: success,
}

/// bridge-out step2
#[derive(Deserialize)]
pub struct BridgeOutTransactionPrepare {
    pub instance_id: String,
    // GOAT txid
    pub pegout_txid: String,
    // For double check with operator selected in peg out txn
    pub operator: String,
}

#[derive(Deserialize, Serialize)]
pub struct BridgeOutTransactionPrepareResponse {
    pub instance_id: String,
    pub btc_hashed_timelock_utxo: UTXO,
    /// BTC address
    pub operator_refund_address: String,
}

// handler: committee
#[derive(Deserialize)]
pub struct BridgeOutUserClaimRequest {
    pub instance_id: String,
    // hex
    pub pegout_txid: String,
    pub signed_claim_txn: String,
}

#[derive(Deserialize, Serialize)]
pub struct BridgeOutUserClaimResponse {
    pub instance_id: String,
    pub claim_txid: String,
}


/// get tx detail
#[derive(Deserialize)]
pub struct InstanceListRequest {
    pub user_address: String,

    pub offset: u32,
    pub limit: u32,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceListResponse {
    //                               // instance_id -> (txid, bridge_path)
    pub instances: Vec<Instance>, // HashMap<String, (String, String)>
}

#[derive(Deserialize)]
pub struct InstanceGetRequest {
    pub instance_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct InstanceGetResponse {
    pub instance: Instance,
}


/// graph_overview

// All fields can be optional
// if all are none, we fetch all the graph list order by timestamp desc.
#[derive(Deserialize)]
pub struct GraphListRequest {
    pub role: String,
    pub status: GraphStatus,
    pub operator: String,
    pub pegin_txid: String,

    pub offset: u32,
    pub limit: u32,
}

#[derive(Deserialize, Serialize)]
pub struct GraphListResponse {
    pub graphs: Vec<Graph>,
    pub total_bridge_in_amount: u64,
    pub total_bridge_in_txn: u32,
    pub total_bridge_out_amount: u64,
    pub total_bridge_out_txn: u32,
    pub online_nodes: u32,
    pub total_nodes: u32,
}
use crate::action::{
    GOATMessage, GOATMessageContent, SolderingProofUploaded, push_local_unhandled_messages,
};
use crate::env::{get_bitvm_key, get_proof_build_rpc_host, get_soldering_proof_upload_chunk_bytes};
use crate::rpc_service::AppState;
use crate::rpc_service::response::{ApiResult, ErrorResponse, ok_response, to_api_error};
use crate::utils::{
    SolderingProofUploadKey, SolderingProofUploadMetadata, SolderingProofUploadResponse,
    X_SOLDERING_CHUNK_SHA256, X_SOLDERING_OFFSET, X_SOLDERING_SIGNATURE, X_SOLDERING_TOTAL_LEN,
    load_babe_setup_state, pending_graph_belongs_to_operator, soldering_payload_hash,
    soldering_payload_hash_hex, verify_soldering_proof_upload_signature,
    write_soldering_proof_upload_chunk,
};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Request, Uri};
use bitvm_lib::actors::Actor;
use bitvm_lib::keys::OperatorMasterKey;
use http::StatusCode;
use http_body_util::BodyExt;
use proof_builder::{ChainProofDescRequest, OperatorProofDescRequest, ProofDescResponse};
use reqwest::Url;
use std::sync::Arc;
use uuid::Uuid;

/// Checks if the request host matches the configured proof builder host to prevent forwarding loops.
fn is_loop_detected(env_url: &Url, request_host: Option<&str>) -> bool {
    let Some(req_host_str) = request_host else {
        return false;
    };

    let Some(env_hostname) = env_url.host_str() else {
        return false;
    };

    // Parse Request Host (String split)
    let (req_hostname, req_port_opt) = parse_simple_host_port(req_host_str);

    // Compare Hostnames (case-insensitive)
    if !env_hostname.eq_ignore_ascii_case(&req_hostname) {
        return false;
    }

    let env_port = env_url.port_or_known_default().unwrap_or(0);
    // Compare Ports
    match req_port_opt {
        Some(req_port) => env_port == req_port,
        None => {
            // Request has no explicit port.
            // If Env is using standard ports (80/443), we assume collision is possible/likely.
            // If Env is using a non-standard port (e.g. 8080), and request has NO port (implying 80/443),
            // then they are different.
            env_port == 80 || env_port == 443
        }
    }
}

/// Parses a simple "host" or "host:port" string.
fn parse_simple_host_port(input: &str) -> (String, Option<u16>) {
    let input = input.trim();
    if let Some((host, port_str)) = input.split_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (host.to_string(), Some(port));
    }

    (input.to_string(), None)
}

async fn handle_proof_desc_forwarding(
    uri: &Uri,
    headers: &HeaderMap,
    app_state: Arc<AppState>,
    error_code: &str,
) -> ApiResult<ProofDescResponse> {
    match get_proof_build_rpc_host() {
        Some(host) => {
            // Strict check: parse as URL and validate scheme
            let Some(env_url) =
                Url::parse(&host).ok().filter(|u| u.scheme() == "http" || u.scheme() == "https")
            else {
                tracing::warn!(
                    "GOAT_PROOF_BUILD_URL is invalid (must be valid http/https URL): {host}"
                );
                return ok_response(ProofDescResponse {
                    proof_desc: None,
                    error: Some(format!("Invalid GOAT_PROOF_BUILD_URL configuration: {host}")),
                });
            };

            let request_host = headers.get("host").and_then(|h| h.to_str().ok());
            if is_loop_detected(&env_url, request_host) {
                tracing::warn!(
                    "GOAT_PROOF_BUILD_URL points to self ({host}), returning mock data to avoid loop"
                );
                return ok_response(ProofDescResponse {
                    proof_desc: None,
                    error: Some("Request host matches self, loop detected".to_string()),
                });
            }

            let base_url = env_url.as_str().trim_end_matches('/');
            let url = format!("{base_url}{uri}");

            let resp =
                app_state.http_client.get_response_json::<ProofDescResponse>(&url).await.map_err(
                    |e| {
                        to_api_error(
                            error_code,
                            format!("fail to get proof from url: {host}, error: {e}"),
                        )
                    },
                )?;
            ok_response(resp)
        }
        None => ok_response(ProofDescResponse {
            proof_desc: None,
            error: Some("env GOAT_PROOF_BUILD_URL needs to be set".to_string()),
        }),
    }
}

/// Get chain proof description
///
/// Retrieves proof description information for a specific chain proof type. If the `GOAT_PROOF_BUILD_URL`
/// environment variable is set, the request is forwarded to the specified proof builder RPC service.
/// Otherwise, returns mock proof data for testing purposes. Includes loop detection to prevent infinite
/// forwarding when the environment variable points to the current service.
///
/// # Query Parameters
///
/// - `proof_type`: Proof type (required) - one of `header_chain`, `commit_chain`, or `state_chain`
/// - `height`: Block height (optional) - specific block height to query proof for
///
/// # Returns
///
/// Returns `ApiResult<ProofDescResponse>` which wraps the response in HTTP status code and JSON format:
///
/// - **Success (200 OK)**: Returns `ProofDescResponse` JSON containing:
///   - `proof_desc`: Optional `ProofDesc` object with proof metadata (block range, proof state, proving cycles, timing information, etc.)
///   - `error`: Optional error message string (may be present even with 200 status if forwarding loop detected)
///
/// - **Error (500 Internal Server Error)**: Returns `ErrorResponse` JSON containing:
///   - `error`: Error code string (e.g., "GET_CHAIN_PROOF_ERROR")
///   - `message`: Detailed error message describing what went wrong
///
/// # Use Case
///
/// Applications use this to retrieve proof generation status and metadata for different chain proof types
/// in the BitVM network. The endpoint supports forwarding requests to dedicated proof builder services
/// when configured via environment variables.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/chain_proofs_desc?proof_type=header_chain&height=100000&is_start_height=false
/// ```
///
/// Success response example (200 OK):
/// ```json
/// {
///   "proof_desc": {
///     "block_start": 10000,
///     "block_end": 20000,
///     "proof_type": "header_chain",
///     "state": "Proven",
///     "proving_cycles": 10000,
///     "proving_time": 100000,
///     "total_time_to_proof": 100010,
///     "proof_size": 333.0,
///     "zkm_version": "zkm_1.0.0",
///     "pub_values": "abc123...",
///     "prev_proof_number": 1000,
///     "next_proof_number": 1000,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
///
/// Error response example (500 Internal Server Error):
/// ```json
/// {
///   "error": "GET_CHAIN_PROOF_ERROR",
///   "message": "fail to get proof from url: example.com, error: connection failed"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_chain_proof_desc(
    Query(_params): Query<ChainProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ProofDescResponse> {
    handle_proof_desc_forwarding(
        request.uri(),
        request.headers(),
        app_state,
        "GET_CHAIN_PROOF_ERROR",
    )
    .await
}

/// Get operator proof description
///
/// Retrieves proof description information for operator proofs. If the `GOAT_PROOF_BUILD_URL`
/// environment variable is set, the request is forwarded to the specified proof builder RPC service.
/// Otherwise, returns mock proof data for testing purposes. Includes loop detection to prevent infinite
/// forwarding when the environment variable points to the current service.
///
/// # Query Parameters
///
/// - `instance_id`: Instance ID (required) - the identifier of the BitVM instance
/// - `graph_id`: Graph ID (required) - the identifier of the graph within the instance
///
/// # Returns
///
/// Returns `ApiResult<ProofDescResponse>` which wraps the response in HTTP status code and JSON format:
///
/// - **Success (200 OK)**: Returns `ProofDescResponse` JSON containing:
///   - `proof_desc`: Optional `ProofDesc` object with proof metadata (block range, proof state, proving cycles, timing information, etc.)
///   - `error`: Optional error message string (may be present even with 200 status if forwarding loop detected)
///
/// - **Error (500 Internal Server Error)**: Returns `ErrorResponse` JSON containing:
///   - `error`: Error code string (e.g., "GET_OPERATOR_PROOF_ERROR")
///   - `message`: Detailed error message describing what went wrong
///
/// # Use Case
///
/// Applications use this to retrieve proof generation status and metadata for operator proofs
/// in the BitVM network. The endpoint supports forwarding requests to dedicated proof builder services
/// when configured via environment variables.
///
/// # Example
///
/// ```http
/// GET /v1/proofs/operator_proofs_desc?instance_id=instance123&graph_id=graph456
/// ```
///
/// Success response example (200 OK):
/// ```json
/// {
///   "proof_desc": {
///     "block_start": 10000,
///     "block_end": 20000,
///     "proof_type": "OperatorProof",
///     "state": "Proven",
///     "proving_cycles": 10000,
///     "proving_time": 100000,
///     "total_time_to_proof": 100010,
///     "proof_size": 333.0,
///     "zkm_version": "zkm_1.0.0",
///     "pub_values": "abc123...",
///     "prev_proof_number": 1000,
///     "next_proof_number": 1000,
///     "created_at": 1640995200,
///     "updated_at": 1640995200
///   },
///   "error": null
/// }
/// ```
///
/// Error response example (500 Internal Server Error):
/// ```json
/// {
///   "error": "GET_OPERATOR_PROOF_ERROR",
///   "message": "fail to get proof from url: example.com, error: connection failed"
/// }
/// ```
#[axum::debug_handler]
pub async fn get_operator_proof_desc(
    Query(_params): Query<OperatorProofDescRequest>,
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
) -> ApiResult<ProofDescResponse> {
    handle_proof_desc_forwarding(
        request.uri(),
        request.headers(),
        app_state,
        "GET_OPERATOR_PROOF_ERROR",
    )
    .await
}

fn upload_error<T>(status: StatusCode, code: &str, message: impl Into<String>) -> ApiResult<T> {
    Err((status, Json(ErrorResponse { error: code.to_string(), message: message.into() })))
}

fn header_string(headers: &HeaderMap, name: &'static str) -> Result<String, String> {
    headers
        .get(name)
        .ok_or_else(|| format!("missing {name} header"))?
        .to_str()
        .map(str::to_string)
        .map_err(|_| format!("invalid {name} header"))
}

fn parse_usize_header(headers: &HeaderMap, name: &'static str) -> Result<usize, String> {
    header_string(headers, name)?.parse::<usize>().map_err(|_| format!("invalid {name} header"))
}

fn parse_hash_hex(value: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim()).map_err(|_| format!("invalid {name} hex"))?;
    bytes.try_into().map_err(|_| format!("{name} must be 32 bytes"))
}

#[allow(clippy::too_many_arguments)]
async fn validate_soldering_upload_slot(
    app_state: &AppState,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_index: usize,
) -> Result<bitcoin::PublicKey, String> {
    if app_state.actor != Actor::Operator {
        return Err("soldering proof upload is only accepted by Operator".to_string());
    }
    let operator_master_key =
        OperatorMasterKey::new(get_bitvm_key().map_err(|err| err.to_string())?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    let belongs = pending_graph_belongs_to_operator(
        &app_state.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await
    .map_err(|err| err.to_string())?;
    if !belongs {
        return Err("no local pending graph session for this Operator".to_string());
    }
    let state = load_babe_setup_state(&app_state.local_db, instance_id, graph_id)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("missing BABE setup state for pending graph {graph_id}"))?;
    let operator_state = state
        .operator
        .as_ref()
        .ok_or_else(|| format!("missing operator BABE setup state for pending graph {graph_id}"))?;
    let frozen = operator_state
        .frozen_verifier_pubkeys
        .as_ref()
        .ok_or_else(|| "operator verifier membership is not frozen".to_string())?;
    let verifier_pubkey = *frozen
        .get(verifier_index)
        .ok_or_else(|| format!("SolderingProof verifier index {verifier_index} out of range"))?;
    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| "selected verifier candidate is missing".to_string())?;
    if candidate.verifier_index != Some(verifier_index) {
        return Err(
            "selected verifier candidate index does not match SolderingProof slot".to_string()
        );
    }
    Ok(verifier_pubkey)
}

/// Upload one raw soldering proof payload chunk.
#[axum::debug_handler]
pub async fn upload_soldering_proof_payload_chunk(
    State(app_state): State<Arc<AppState>>,
    Path((instance_id, graph_id, verifier_index, payload_hash_hex)): Path<(
        Uuid,
        Uuid,
        usize,
        String,
    )>,
    headers: HeaderMap,
    request: Request<Body>,
) -> ApiResult<SolderingProofUploadResponse> {
    let payload_hash = match parse_hash_hex(&payload_hash_hex, "payload_hash") {
        Ok(hash) => hash,
        Err(err) => return upload_error(StatusCode::BAD_REQUEST, "INVALID_PAYLOAD_HASH", err),
    };
    let total_len = match parse_usize_header(&headers, X_SOLDERING_TOTAL_LEN) {
        Ok(value) => value,
        Err(err) => return upload_error(StatusCode::BAD_REQUEST, "INVALID_TOTAL_LEN", err),
    };
    let offset = match parse_usize_header(&headers, X_SOLDERING_OFFSET) {
        Ok(value) => value,
        Err(err) => return upload_error(StatusCode::BAD_REQUEST, "INVALID_OFFSET", err),
    };
    let chunk_hash = match header_string(&headers, X_SOLDERING_CHUNK_SHA256)
        .and_then(|value| parse_hash_hex(&value, X_SOLDERING_CHUNK_SHA256))
    {
        Ok(hash) => hash,
        Err(err) => return upload_error(StatusCode::BAD_REQUEST, "INVALID_CHUNK_HASH", err),
    };
    let signature = match header_string(&headers, X_SOLDERING_SIGNATURE) {
        Ok(value) => value,
        Err(err) => return upload_error(StatusCode::UNAUTHORIZED, "MISSING_SIGNATURE", err),
    };

    let body = match request.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(err) => {
            return upload_error(
                StatusCode::BAD_REQUEST,
                "INVALID_BODY",
                format!("read soldering proof chunk body failed: {err}"),
            );
        }
    };
    if body.is_empty() {
        return upload_error(StatusCode::BAD_REQUEST, "EMPTY_CHUNK", "chunk body is empty");
    }
    let max_chunk_bytes = get_soldering_proof_upload_chunk_bytes();
    if body.len() > max_chunk_bytes {
        return upload_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "CHUNK_TOO_LARGE",
            format!("chunk len {} exceeds max {max_chunk_bytes}", body.len()),
        );
    }
    if soldering_payload_hash(&body) != chunk_hash {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "CHUNK_HASH_MISMATCH",
            "chunk hash does not match request body",
        );
    }
    let metadata = SolderingProofUploadMetadata {
        instance_id,
        graph_id,
        verifier_index,
        payload_hash,
        total_len,
        offset,
        chunk_len: body.len(),
    };
    let verifier_pubkey =
        match validate_soldering_upload_slot(&app_state, instance_id, graph_id, verifier_index)
            .await
        {
            Ok(pubkey) => pubkey,
            Err(err) => {
                tracing::warn!(
                    instance_id = %instance_id,
                    graph_id = %graph_id,
                    verifier_index,
                    error = %err,
                    "reject soldering proof upload before write"
                );
                return upload_error(StatusCode::FORBIDDEN, "UPLOAD_FORBIDDEN", err);
            }
        };
    if let Err(err) = verify_soldering_proof_upload_signature(
        &verifier_pubkey,
        &signature,
        &metadata,
        &chunk_hash,
    ) {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            verifier_index,
            offset,
            len = body.len(),
            error = %err,
            "reject soldering proof upload with invalid signature"
        );
        return upload_error(StatusCode::UNAUTHORIZED, "INVALID_SIGNATURE", err.to_string());
    }

    let key = SolderingProofUploadKey::from_ready(&crate::action::SolderingProofReady {
        instance_id,
        graph_id,
        verifier_index,
        payload_hash,
        total_len,
        upload_chunk_bytes: max_chunk_bytes,
    });
    let write_result = match write_soldering_proof_upload_chunk(
        &app_state.local_db,
        &key,
        total_len,
        offset,
        &body,
        &chunk_hash,
    ) {
        Ok(result) => result,
        Err(err) => {
            let msg = err.to_string();
            let status =
                if msg.contains("offset") || msg.contains("conflict") || msg.contains("overlap") {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_REQUEST
                };
            tracing::warn!(
                instance_id = %instance_id,
                graph_id = %graph_id,
                verifier_index,
                offset,
                len = body.len(),
                error = %msg,
                "soldering proof upload chunk rejected while writing"
            );
            return upload_error(status, "UPLOAD_CHUNK_REJECTED", msg);
        }
    };
    tracing::info!(
        instance_id = %instance_id,
        graph_id = %graph_id,
        verifier_index,
        offset,
        len = body.len(),
        received = write_result.received,
        total = write_result.total_len,
        "received soldering proof upload chunk"
    );

    if write_result.complete {
        tracing::info!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            verifier_index,
            total_len,
            payload_hash = %soldering_payload_hash_hex(&payload_hash),
            payload_path = ?write_result.payload_path,
            "soldering proof upload completed"
        );
        let message = GOATMessage::new(
            Actor::Operator,
            GOATMessageContent::SolderingProofUploaded(SolderingProofUploaded {
                instance_id,
                graph_id,
                verifier_index,
                payload_hash,
                total_len,
            }),
        );
        if let Err(err) =
            push_local_unhandled_messages(&app_state.local_db, instance_id, &message, 0).await
        {
            tracing::error!(
                instance_id = %instance_id,
                graph_id = %graph_id,
                verifier_index,
                error = %err,
                "failed to enqueue local SolderingProofUploaded message"
            );
            return upload_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ENQUEUE_FAILED",
                err.to_string(),
            );
        }
        tracing::info!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            verifier_index,
            "queued local SolderingProofUploaded message"
        );
    }

    ok_response(SolderingProofUploadResponse {
        received: write_result.received,
        total_len: write_result.total_len,
        complete: write_result.complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_host_port() {
        assert_eq!(parse_simple_host_port("example.com"), ("example.com".to_string(), None));
        assert_eq!(
            parse_simple_host_port("example.com:8080"),
            ("example.com".to_string(), Some(8080))
        );
        assert_eq!(
            parse_simple_host_port("192.168.1.1:3000"),
            ("192.168.1.1".to_string(), Some(3000))
        );
    }

    #[test]
    fn test_is_loop_detected_standard_ports() {
        // Same host, standard ports
        let u1 = Url::parse("http://example.com").unwrap();
        assert!(is_loop_detected(&u1, Some("example.com")));

        let u2 = Url::parse("https://example.com").unwrap();
        assert!(is_loop_detected(&u2, Some("example.com")));

        // Explicit ports matching defaults
        let u3 = Url::parse("http://example.com:80").unwrap();
        assert!(is_loop_detected(&u3, Some("example.com:80")));

        let u4 = Url::parse("https://example.com:443").unwrap();
        assert!(is_loop_detected(&u4, Some("example.com:443")));

        // Mixing implicit and explicit standard ports
        assert!(is_loop_detected(&u1, Some("example.com:80")));
        assert!(is_loop_detected(&u3, Some("example.com")));
    }

    #[test]
    fn test_is_loop_detected_non_standard_ports() {
        let u = Url::parse("http://example.com:8080").unwrap();

        // Same host, same non-standard port -> Loop
        assert!(is_loop_detected(&u, Some("example.com:8080")));

        // Same host, different ports -> No Loop
        assert!(!is_loop_detected(&u, Some("example.com:9090")));

        // Env uses non-standard, Req uses implicit (std) -> No Loop
        assert!(!is_loop_detected(&u, Some("example.com")));
    }

    #[test]
    fn test_is_loop_detected_mismatch_host() {
        let u = Url::parse("http://example.com").unwrap();
        assert!(!is_loop_detected(&u, Some("other.com")));
        assert!(!is_loop_detected(&u, Some("sub.example.com")));
    }

    #[test]
    fn test_is_loop_detected_case_insensitive() {
        let u1 = Url::parse("HTTP://EXAMPLE.COM").unwrap();
        assert!(is_loop_detected(&u1, Some("example.com")));

        let u2 = Url::parse("http://example.com").unwrap();
        assert!(is_loop_detected(&u2, Some("EXAMPLE.COM")));
    }
}

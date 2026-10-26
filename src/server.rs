// Copyright (c) 2026 The SideBoost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! The part of the enforcer's `cusf.mainchain.v1` API a SideBoost node uses,
//! in the JSON form of the Connect protocol over HTTP/1.1 (POST
//! `/cusf.mainchain.v1.<Service>/<Method>`), with the replies a full
//! enforcer gives:
//!
//! - `ValidatorService/GetChainTip`
//! - `ValidatorService/GetBlockHeaderInfo`
//! - `ValidatorService/GetTwoWayPegData`, for the slot followed only
//!
//! Anything else, including the block producer (a light enforcer can't
//! mine), is answered as unimplemented.

use std::{str::FromStr as _, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bitcoin::BlockHash;
use serde_json::{Value, json};

use crate::{
    bip300::Event,
    chain::{Chain, HeaderInfo},
    node::Node,
    scanner::{PegDataError, Scanner},
};

const PREFIX: &str = "/cusf.mainchain.v1.";

/// A Connect error: an HTTP status and a code
struct ConnectError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ConnectError {
    fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_argument",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "unavailable",
            message: message.into(),
        }
    }

    fn unimplemented(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            code: "unimplemented",
            message: message.into(),
        }
    }
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

impl IntoResponse for ConnectError {
    fn into_response(self) -> Response {
        json_response(self.status, &json!({ "code": self.code, "message": self.message }))
    }
}

struct State {
    node: Arc<Node>,
    scanner: Arc<Scanner>,
    slot: u8,
}

pub fn router(node: Arc<Node>, scanner: Arc<Scanner>, slot: u8) -> Router {
    let state = Arc::new(State { node, scanner, slot });
    Router::new().fallback(move |uri: Uri, body: Bytes| {
        let state = state.clone();
        async move {
            match handle(&state, &uri, &body) {
                Ok(reply) => json_response(StatusCode::OK, &reply),
                Err(err) => err.into_response(),
            }
        }
    })
}

fn handle(state: &State, uri: &Uri, body: &[u8]) -> Result<Value, ConnectError> {
    let method = uri
        .path()
        .strip_prefix(PREFIX)
        .ok_or_else(|| ConnectError::not_found(format!("no such path: {}", uri.path())))?;
    let request: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(body)
            .map_err(|err| ConnectError::invalid_argument(format!("request is not JSON: {err}")))?
    };
    match method {
        "ValidatorService/GetChainTip" => {
            let tip = state
                .scanner
                .tip()
                .ok_or_else(|| ConnectError::unavailable("Validator is not synced"))?;
            Ok(json!({ "blockHeaderInfo": header_info(&tip) }))
        }
        "ValidatorService/GetBlockHeaderInfo" => {
            let hash = hash_field(&request, "blockHash")?
                .ok_or_else(|| ConnectError::invalid_argument("missing blockHash"))?;
            let max_ancestors = request.get("maxAncestors").and_then(Value::as_u64).unwrap_or(0);
            let infos = state.node.with_chain(|chain| ancestors(chain, hash, max_ancestors));
            Ok(if infos.is_empty() {
                json!({})
            } else {
                json!({ "headerInfos": infos.iter().map(header_info).collect::<Vec<_>>() })
            })
        }
        "ValidatorService/GetTwoWayPegData" => {
            let slot = request.get("sidechainId").and_then(Value::as_u64);
            if slot != Some(u64::from(state.slot)) {
                return Err(ConnectError::invalid_argument(format!(
                    "this light enforcer follows sidechain {} only",
                    state.slot
                )));
            }
            let start = hash_field(&request, "startBlockHash")?;
            let end = hash_field(&request, "endBlockHash")?
                .ok_or_else(|| ConnectError::invalid_argument("missing endBlockHash"))?;
            let blocks = state.scanner.two_way_peg_data(start, end).map_err(|err| match err {
                PegDataError::EndNotFound(_) => ConnectError::not_found(err.to_string()),
                PegDataError::StartNotAncestor { .. } => ConnectError::invalid_argument(err.to_string()),
            })?;
            let blocks: Vec<_> = blocks
                .iter()
                .map(|(info, events)| {
                    json!({
                        "blockHeaderInfo": header_info(info),
                        "blockInfo": { "events": events.iter().map(event).collect::<Vec<_>>() },
                    })
                })
                .collect();
            Ok(if blocks.is_empty() {
                json!({})
            } else {
                json!({ "blocks": blocks })
            })
        }
        _ if method.starts_with("BlockProducerService/") => Err(ConnectError::unimplemented(
            "a light enforcer can't produce blocks: proposing withdrawal bundles and voting for them need a miner's full enforcer",
        )),
        _ => Err(ConnectError::unimplemented(format!(
            "{method} is not served by a light enforcer"
        ))),
    }
}

/// A `ReverseHex` block hash field, if present
fn hash_field(request: &Value, key: &str) -> Result<Option<BlockHash>, ConnectError> {
    let Some(field) = request.get(key) else {
        return Ok(None);
    };
    field
        .get("hex")
        .and_then(Value::as_str)
        .and_then(|hex| BlockHash::from_str(hex).ok())
        .map(Some)
        .ok_or_else(|| ConnectError::invalid_argument(format!("bad {key}")))
}

/// `hash` and up to `max_ancestors` of its ancestors, newest first
fn ancestors(chain: &Chain, hash: BlockHash, max_ancestors: u64) -> Vec<HeaderInfo> {
    let mut res = Vec::new();
    let mut next = chain.get(&hash);
    while let Some(info) = next {
        res.push(info);
        if res.len() as u64 > max_ancestors || info.height == 0 {
            break;
        }
        next = chain.get(&info.prev_hash);
    }
    res
}

fn header_info(info: &HeaderInfo) -> Value {
    let mut res = json!({
        "blockHash": { "hex": info.hash.to_string() },
        "prevBlockHash": { "hex": info.prev_hash.to_string() },
        "work": { "hex": hex::encode(info.work().to_le_bytes()) },
        "timestamp": info.time.to_string(),
    });
    // Protobuf's JSON leaves out zero scalars
    if info.height != 0 {
        res["height"] = json!(info.height);
    }
    res
}

/// Protobuf's JSON carries 64-bit integers as strings
fn event(event: &Event) -> Value {
    match event {
        Event::Deposit {
            sequence,
            outpoint,
            address,
            value,
        } => json!({ "deposit": {
            "sequenceNumber": sequence.to_string(),
            "outpoint": { "txid": { "hex": outpoint.txid.to_string() }, "vout": outpoint.vout },
            "output": { "address": { "hex": hex::encode(address) }, "valueSats": value.to_string() },
        }}),
        Event::BundleSubmitted { m6id } => bundle_event(m6id, json!({ "submitted": {} })),
        Event::BundleFailed { m6id } => bundle_event(m6id, json!({ "failed": {} })),
        Event::BundleSucceeded {
            m6id,
            sequence,
            transaction,
        } => bundle_event(
            m6id,
            json!({ "succeeded": {
                "sequenceNumber": sequence.to_string(),
                "transaction": { "hex": hex::encode(transaction) },
            }}),
        ),
    }
}

fn bundle_event(m6id: &[u8; 32], event: Value) -> Value {
    json!({ "withdrawalBundle": { "m6id": { "hex": hex::encode(m6id) }, "event": event } })
}

use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use charms_client::tx::EnchantedTx;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create router
    let app = Router::new()
        .route("/extract_spell", post(extract_spell_handler))
        .route("/verify_snark", post(verify_snark_handler))
        .route("/health", get(health_check));

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct ExtractSpellRequest {
    tx_hex: String,
    spell_vk: String,
    mock: Option<bool>,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error_with_data<E>(error: String) -> ApiResponse<E> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

async fn extract_spell_handler(
    Json(request): Json<ExtractSpellRequest>,
) -> (StatusCode, AxumJson<ApiResponse<serde_json::Value>>) {
    match process_extract_spell(&request.tx_hex, &request.spell_vk, request.mock.unwrap_or(false)).await {
        Ok(spell_data) => {
            match serde_json::to_value(&spell_data) {
                Ok(json_value) => (StatusCode::OK, AxumJson(ApiResponse::success(json_value))),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    AxumJson(ApiResponse::<serde_json::Value>::error_with_data(format!("JSON serialization error: {}", e))),
                ),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            AxumJson(ApiResponse::<serde_json::Value>::error_with_data(e.to_string())),
        ),
    }
}

#[derive(Deserialize)]
struct VerifySnarkRequest {
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
    vk_hash: String,
    spell_version: u32,
    mock: Option<bool>,
}

async fn verify_snark_handler(
    Json(request): Json<VerifySnarkRequest>,
) -> (StatusCode, AxumJson<ApiResponse<bool>>) {
    match process_verify_snark(
        &request.proof,
        &request.public_inputs,
        &request.vk_hash,
        request.spell_version,
        request.mock.unwrap_or(false),
    ).await {
        Ok(is_valid) => (StatusCode::OK, AxumJson(ApiResponse::success(is_valid))),
        Err(e) => (
            StatusCode::OK, // Still return 200 for verification failures
            AxumJson(ApiResponse::<bool>::error_with_data(e.to_string())),
        ),
    }
}

async fn health_check() -> (StatusCode, AxumJson<serde_json::Value>) {
    (StatusCode::OK, AxumJson(serde_json::json!({"status": "healthy"})))
}

async fn process_extract_spell(
    tx_hex: &str,
    spell_vk: &str,
    mock: bool,
) -> anyhow::Result<charms_client::NormalizedSpell> {
    let bitcoin_tx = charms_client::bitcoin_tx::BitcoinTx::from_hex(tx_hex)?;
    bitcoin_tx.extract_and_verify_spell(spell_vk, mock)
}

async fn process_verify_snark(
    proof: &[u8],
    public_inputs: &[u8],
    vk_hash: &str,
    spell_version: u32,
    mock: bool,
) -> anyhow::Result<bool> {
    charms_client::tx::verify_snark_proof(proof, public_inputs, vk_hash, spell_version, mock)?;
    Ok(true)
}

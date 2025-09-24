use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Instant;
use charms_client::tx::EnchantedTx;

/// Charms verification parser server
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to bind the server to
    #[arg(short, long, default_value_t = 3000)]
    port: u16,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create router
    let app = Router::new()
        .route("/extract_spell", post(extract_spell_handler))
        .route("/verify_snark", post(verify_snark_handler))
        .route("/health", get(health_check))
        .layer(axum::middleware::from_fn(request_logging_middleware));

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    tracing::info!("🚀 Server starting on http://{}", addr);
    tracing::info!("📊 Available endpoints:");
    tracing::info!("   POST /extract_spell - Extract and verify Bitcoin transaction spells");
    tracing::info!("   POST /verify_snark - Verify SNARK proofs");
    tracing::info!("   GET  /health - Health check");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("✅ Server successfully started and listening for requests");

    // Add shutdown signal handling for graceful shutdown
    let (tx, rx) = tokio::sync::oneshot::channel();

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("🛑 Received shutdown signal, gracefully shutting down...");
            let _ = tx.send(());
            rx.await.ok();
        })
        .await
        .unwrap();

    tracing::info!("👋 Server shutdown complete");
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
    let tx_hex_len = request.tx_hex.len();
    tracing::debug!("Extract spell request: tx_hex length = {}", tx_hex_len);

    match process_extract_spell(&request.tx_hex, &request.spell_vk, request.mock.unwrap_or(false)).await {
        Ok(spell_data) => {
            tracing::info!("Spell extraction successful for tx_hex (length: {})", tx_hex_len);
            match serde_json::to_value(&spell_data) {
                Ok(json_value) => {
                    tracing::debug!("Spell data serialized successfully");
                    (StatusCode::OK, AxumJson(ApiResponse::success(json_value)))
                },
                Err(e) => {
                    tracing::error!("Failed to serialize spell data: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        AxumJson(ApiResponse::<serde_json::Value>::error_with_data(format!("JSON serialization error: {}", e))),
                    )
                },
            }
        }
        Err(e) => {
            tracing::warn!("Spell extraction failed for tx_hex (length: {}): {}", tx_hex_len, e);
            (
                StatusCode::BAD_REQUEST,
                AxumJson(ApiResponse::<serde_json::Value>::error_with_data(e.to_string())),
            )
        },
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
    let proof_len = request.proof.len();
    let public_inputs_len = request.public_inputs.len();
    tracing::debug!(
        "Verify SNARK request: proof_len = {}, public_inputs_len = {}, spell_version = {}",
        proof_len,
        public_inputs_len,
        request.spell_version
    );

    match process_verify_snark(
        &request.proof,
        &request.public_inputs,
        &request.vk_hash,
        request.spell_version,
        request.mock.unwrap_or(false),
    ).await {
        Ok(is_valid) => {
            tracing::info!(
                "SNARK verification {} for spell_version {} (proof: {} bytes, public_inputs: {} bytes)",
                if is_valid { "successful" } else { "failed" },
                request.spell_version,
                proof_len,
                public_inputs_len
            );
            (StatusCode::OK, AxumJson(ApiResponse::success(is_valid)))
        },
        Err(e) => {
            tracing::warn!(
                "SNARK verification error for spell_version {} (proof: {} bytes, public_inputs: {} bytes): {}",
                request.spell_version,
                proof_len,
                public_inputs_len,
                e
            );
            (
                StatusCode::OK, // Still return 200 for verification failures
                AxumJson(ApiResponse::<bool>::error_with_data(e.to_string())),
            )
        },
    }
}

async fn health_check() -> (StatusCode, AxumJson<serde_json::Value>) {
    tracing::debug!("Health check requested");
    (StatusCode::OK, AxumJson(serde_json::json!({"status": "healthy"})))
}

/// 请求日志中间件
async fn request_logging_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let version = request.version();

    // 记录请求开始
    tracing::info!(
        "→ {} {} {:?}",
        method,
        uri,
        version
    );

    // 如果是POST请求，记录请求体大小（不记录具体内容以避免敏感数据泄露）
    if method == axum::http::Method::POST {
        if let Some(content_length) = request.headers().get("content-length") {
            tracing::debug!("Request body size: {} bytes", content_length.to_str().unwrap_or("unknown"));
        }
    }

    // 处理请求
    let response = next.run(request).await;

    // 计算处理时间
    let duration = start.elapsed();
    let status = response.status();

    // 记录响应信息
    tracing::info!(
        "← {} {} - {} - {:?}",
        method,
        uri,
        status,
        duration
    );

    // 如果是错误响应，记录更多调试信息
    if !status.is_success() {
        tracing::warn!(
            "Request failed: {} {} -> {} ({:?})",
            method,
            uri,
            status,
            duration
        );
    }

    response
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

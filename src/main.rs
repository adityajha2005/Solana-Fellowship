use axum::{extract::Json as AxumJson, http::StatusCode, response::{IntoResponse, Json}, routing::post, Router};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json;
use solana_sdk::{signature::{Keypair, Signer}, pubkey::Pubkey};
use spl_token::{instruction as spl_instruction, ID as TOKEN_PROGRAM_ID};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair_handler))
        .route("/token/create", post(create_token_handler))
        .route("/token/mint", post(mint_token_handler));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("Failed to bind to port 3001");
    
    println!("Solana HTTP server running on http://0.0.0.0:3001");
    axum::serve(listener, app).await.unwrap();
}
//response structure
#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

//keypair response data
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

//token creation request
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

//mint token request
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

//account metadata for response
#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

//token creation response data
#[derive(Serialize)]
struct CreateTokenData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

fn success_response<T: Serialize>(data: T) -> (StatusCode, Json<SuccessResponse<T>>) {
    (
        StatusCode::OK,
        Json(SuccessResponse {
            success: true,
            data,
        }),
    )
}

//POST /keypair
async fn generate_keypair_handler() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    let secret_bytes = keypair.to_bytes();
    let secret_base58 = bs58::encode(&secret_bytes).into_string();
    //public key to base58
    let pubkey_base58 = pubkey.to_string();
    let keypair_data = KeypairData {
        pubkey: pubkey_base58,
        secret: secret_base58,
    };
    
    success_response(keypair_data)
}

//POST /token/create
async fn create_token_handler(AxumJson(request): AxumJson<CreateTokenRequest>) -> Json<serde_json::Value> {
    let mint_authority = match Pubkey::from_str(&request.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint authority public key"
            }));
        }
    };
    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };
    
    let instruction_result = spl_instruction::initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint,
        &mint_authority,
        None, 
        request.decimals,
    );
    
    match instruction_result {
        Ok(inst) => {
            let accounts: Vec<AccountInfo> = inst.accounts
                .iter()
                .map(|acc| AccountInfo {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                })
                .collect();
            
            let instruction_data = general_purpose::STANDARD.encode(&inst.data);
            
            let token_data = CreateTokenData {
                program_id: inst.program_id.to_string(),
                accounts,
                instruction_data,
            };
            
            Json(serde_json::json!({
                "success": true,
                "data": token_data
            }))
        }
        Err(e) => {
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create token instruction: {}", e)
            }))
        }
    }
}

//POST /token/mint
async fn mint_token_handler(AxumJson(request): AxumJson<MintTokenRequest>) -> Json<serde_json::Value> {
    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };
    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            }));
        }
    };
    
    let authority = match Pubkey::from_str(&request.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Invalid authority public key"
            }));
        }
    };
    
    let instruction_result = spl_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination,
        &authority,
        &[],  
        request.amount,
    );
    
    match instruction_result {
        Ok(inst) => {
            let accounts: Vec<AccountInfo> = inst.accounts
                .iter()
                .map(|acc| AccountInfo {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                })
                .collect();
            
            let instruction_data = general_purpose::STANDARD.encode(&inst.data);
            
            let mint_data = CreateTokenData {
                program_id: inst.program_id.to_string(),
                accounts,
                instruction_data,
            };
            
            Json(serde_json::json!({
                "success": true,
                "data": mint_data
            }))
        }
        Err(e) => {
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to create mint instruction: {}", e)
            }))
        }
    }
}

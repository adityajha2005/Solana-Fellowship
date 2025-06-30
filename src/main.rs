use axum::{extract::Json, http::StatusCode, response::{IntoResponse, Json as ResponseJson}, routing::post, Router};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_associated_token_account;
use spl_token::{instruction as spl_instruction, ID as TOKEN_PROGRAM_ID};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("Failed to bind to port 3001");
    
    println!("Solana HTTP server running on http://0.0.0.0:3001 - UPDATED VERSION WITH STATUS CODES");
    axum::serve(listener, app).await.unwrap();
}

// Request structures
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: Option<u8>,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: Option<String>,
    destination: Option<String>,
    authority: Option<String>,
    #[serde(deserialize_with = "deserialize_amount")]
    amount: Option<u64>,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: Option<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: Option<String>,
    signature: Option<String>,
    pubkey: Option<String>,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: Option<String>,
    to: Option<String>,
    #[serde(deserialize_with = "deserialize_amount")]
    lamports: Option<u64>,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    #[serde(deserialize_with = "deserialize_amount")]
    amount: Option<u64>,
}

// Custom deserializer to handle both string and number amounts
fn deserialize_amount<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct AmountVisitor;

    impl<'de> Visitor<'de> for AmountVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number or string representing an amount")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<u64>()
                .map(Some)
                .map_err(|_| de::Error::custom("Invalid amount format"))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(AmountVisitor)
}

// Response structures
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<SendTokenAccountInfo>,
    instruction_data: String,
}

// Helper functions
fn success_response(data: impl Serialize) -> (StatusCode, ResponseJson<Value>) {
    (StatusCode::OK, ResponseJson(json!({
        "success": true,
        "data": data
    })))
}

fn error_response(error: &str) -> (StatusCode, ResponseJson<Value>) {
    (StatusCode::BAD_REQUEST, ResponseJson(json!({
        "success": false,
        "error": error
    })))
}

fn parse_pubkey(pubkey_str: &str, field_name: &str) -> Result<Pubkey, String> {
    // Additional validation for pubkey format
    if pubkey_str.len() < 32 || pubkey_str.len() > 44 {
        return Err(format!("Invalid {} address format", field_name));
    }
    
    Pubkey::from_str(pubkey_str)
        .map_err(|_| format!("Invalid {} address", field_name))
}



fn validate_positive_amount(amount: u64, field_name: &str) -> Result<(), String> {
    if amount == 0 {
        return Err(format!("Invalid {} - amount must be greater than 0", field_name));
    }
    // Additional validation for reasonable limits
    if amount > u64::MAX / 2 {
        return Err(format!("Invalid {} - amount too large", field_name));
    }
    Ok(())
}

fn validate_decimals(decimals: u8) -> Result<(), String> {
    if decimals > 9 {
        return Err("Invalid decimals - maximum allowed is 9".to_string());
    }
    Ok(())
}

// Endpoint handlers
async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let secret_base58 = bs58::encode(&keypair.to_bytes()).into_string();
    let pubkey_base58 = keypair.pubkey().to_string();
    
    let keypair_data = KeypairData {
        pubkey: pubkey_base58,
        secret: secret_base58,
    };
    
    success_response(keypair_data)
}

async fn create_token(Json(request): Json<CreateTokenRequest>) -> impl IntoResponse {
    // Validate required fields are present and not empty
    let mint_authority_str = match request.mint_authority {
        Some(ref ma) if !ma.trim().is_empty() => ma.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let mint_str = match request.mint {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let decimals = match request.decimals {
        Some(d) => d,
        None => return error_response("Missing required fields"),
    };
    
    // Validate decimals
    if let Err(e) = validate_decimals(decimals) {
        return error_response(&e);
    }
    
    let mint_authority = match parse_pubkey(mint_authority_str, "mint authority") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let mint = match parse_pubkey(mint_str, "mint") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    // Prevent self-authorization for security
    if mint_authority == mint {
        return error_response("Mint and mint authority cannot be the same");
    }
    
    let instruction = match spl_instruction::initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint,
        &mint_authority,
        None,
        decimals,
    ) {
        Ok(inst) => inst,
        Err(e) => return error_response(&format!("Failed to create token instruction: {}", e)),
    };
    
    let accounts: Vec<AccountInfo> = instruction.accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let token_data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    success_response(token_data)
}

async fn mint_token(Json(request): Json<MintTokenRequest>) -> impl IntoResponse {
    // Validate required fields are present and not empty
    let mint_str = match request.mint {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let destination_str = match request.destination {
        Some(ref d) if !d.trim().is_empty() => d.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let authority_str = match request.authority {
        Some(ref a) if !a.trim().is_empty() => a.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let amount = match request.amount {
        Some(amt) => {
            if let Err(e) = validate_positive_amount(amt, "amount") {
                return error_response(&e);
            }
            amt
        },
        None => return error_response("Missing required fields"),
    };
    
    let mint = match parse_pubkey(mint_str, "mint") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let destination = match parse_pubkey(destination_str, "destination") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let authority = match parse_pubkey(authority_str, "authority") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    // Prevent minting to the same address as mint for security
    if destination == mint {
        return error_response("Destination cannot be the same as mint address");
    }
    
    let instruction = match spl_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination,
        &authority,
        &[],
        amount,
    ) {
        Ok(inst) => inst,
        Err(e) => return error_response(&format!("Failed to create mint instruction: {}", e)),
    };
    
    let accounts: Vec<AccountInfo> = instruction.accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let mint_data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    success_response(mint_data)
}

async fn sign_message(Json(request): Json<SignMessageRequest>) -> impl IntoResponse {
    // Validate required fields are present and not empty
    let message = match request.message {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let secret = match request.secret {
        Some(ref s) if !s.trim().is_empty() => s.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    // Validate message length for security
    if message.len() > 1024 {
        return error_response("Message too long - maximum 1024 characters");
    }
    
    let secret_bytes = match bs58::decode(secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid secret key format"),
    };
    
    if secret_bytes.len() != 64 {
        return error_response("Invalid secret key length");
    }
    
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return error_response("Invalid secret key"),
    };
    
    let signature = keypair.sign_message(message.as_bytes());
    let signature_base64 = general_purpose::STANDARD.encode(signature.as_ref());
    
    let sign_data = SignMessageData {
        signature: signature_base64,
        public_key: keypair.pubkey().to_string(),
        message: message.to_string(),
    };
    
    success_response(sign_data)
}

async fn verify_message(Json(request): Json<VerifyMessageRequest>) -> impl IntoResponse {
    // Validate required fields are present and not empty
    let message = match request.message {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let signature_str = match request.signature {
        Some(ref s) if !s.trim().is_empty() => s.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let pubkey_str = match request.pubkey {
        Some(ref p) if !p.trim().is_empty() => p.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    // Validate message length for security
    if message.len() > 1024 {
        return error_response("Message too long - maximum 1024 characters");
    }
    
    let pubkey = match parse_pubkey(pubkey_str, "public key") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let signature_bytes = match general_purpose::STANDARD.decode(signature_str) {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid signature format"),
    };
    
    if signature_bytes.len() != 64 {
        return error_response("Invalid signature length");
    }
    
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return error_response("Invalid signature"),
    };
    
    let is_valid = signature.verify(&pubkey.to_bytes(), message.as_bytes());
    
    let verify_data = VerifyMessageData {
        valid: is_valid,
        message: message.to_string(),
        pubkey: pubkey_str.to_string(),
    };
    
    success_response(verify_data)
}

async fn send_sol(Json(request): Json<SendSolRequest>) -> impl IntoResponse {
    // Validate required fields are present and not empty
    let from = match request.from {
        Some(ref f) if !f.trim().is_empty() => f.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let to = match request.to {
        Some(ref t) if !t.trim().is_empty() => t.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let lamports = match request.lamports {
        Some(l) => {
            if let Err(e) = validate_positive_amount(l, "lamports") {
                return error_response(&e);
            }
            l
        },
        None => return error_response("Missing required fields"),
    };
    
    let from_pubkey = match parse_pubkey(from, "from") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let to_pubkey = match parse_pubkey(to, "to") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    // Prevent self-transfer for security
    if from_pubkey == to_pubkey {
        return error_response("Cannot transfer to the same address");
    }
    
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, lamports);
    
    let accounts: Vec<String> = instruction.accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let sol_data = SendSolData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    success_response(sol_data)
}

async fn send_token(Json(request): Json<SendTokenRequest>) -> impl IntoResponse {
    // Validate required fields are present and not empty
    let destination = match request.destination {
        Some(ref dest) if !dest.trim().is_empty() => dest.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let mint = match request.mint {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let owner = match request.owner {
        Some(ref o) if !o.trim().is_empty() => o.trim(),
        _ => return error_response("Missing required fields"),
    };
    
    let amount = match request.amount {
        Some(amt) => {
            if let Err(e) = validate_positive_amount(amt, "amount") {
                return error_response(&e);
            }
            amt
        },
        None => return error_response("Missing required fields"),
    };
    
    let destination_pubkey = match parse_pubkey(destination, "destination") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let mint_pubkey = match parse_pubkey(mint, "mint") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let owner_pubkey = match parse_pubkey(owner, "owner") {
        Ok(pk) => pk,
        Err(e) => return error_response(&e),
    };
    
    let source_pubkey = spl_associated_token_account::get_associated_token_address(&owner_pubkey, &mint_pubkey);
    
    // Prevent self-transfer for security
    if source_pubkey == destination_pubkey {
        return error_response("Cannot transfer to the same token account");
    }
    
    let instruction = match spl_instruction::transfer(
        &TOKEN_PROGRAM_ID,
        &source_pubkey,
        &destination_pubkey,
        &owner_pubkey,
        &[],
        amount,
    ) {
        Ok(inst) => inst,
        Err(e) => return error_response(&format!("Failed to create transfer instruction: {}", e)),
    };
    
    let accounts: Vec<SendTokenAccountInfo> = instruction.accounts
        .iter()
        .map(|acc| SendTokenAccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);
    
    let token_data = SendTokenData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };
    
    success_response(token_data)
}

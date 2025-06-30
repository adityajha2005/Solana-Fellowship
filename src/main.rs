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
    //routes
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
    
    println!("Server running on port 3001");
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct CreateTokenReq {
    #[serde(rename = "mintAuthority")]
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: Option<u8>,
}

#[derive(Deserialize)]
struct MintTokenReq {
    mint: Option<String>,
    destination: Option<String>,
    authority: Option<String>,
    #[serde(deserialize_with = "parse_amount")]
    amount: Option<u64>,
}

#[derive(Deserialize)]
struct SignMsgReq {
    message: Option<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
struct VerifyMsgReq {
    message: Option<String>,
    signature: Option<String>,
    pubkey: Option<String>,
}

#[derive(Deserialize)]
struct SendSolReq {
    from: Option<String>,
    to: Option<String>,
    #[serde(deserialize_with = "parse_amount")]
    lamports: Option<u64>,
}

#[derive(Deserialize)]
struct SendTokenReq {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    #[serde(deserialize_with = "parse_amount")]
    amount: Option<u64>,
}

fn parse_amount<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct AmtVisitor;

    impl<'de> Visitor<'de> for AmtVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("number or string amount")
        }

        fn visit_u64<E>(self, val: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(val))
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match s.parse::<u64>() {
                Ok(n) => Ok(Some(n)),
                Err(_) => Err(de::Error::custom("bad amount format")),
            }
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

    deserializer.deserialize_any(AmtVisitor)
}

#[derive(Serialize)]
struct KeypairResp {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResp {
    program_id: String,
    accounts: Vec<AccInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignResp {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyResp {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SolTransferResp {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenTransferResp {
    program_id: String,
    accounts: Vec<TokenAccInfo>,
    instruction_data: String,
}

fn ok_response(data: impl Serialize) -> (StatusCode, ResponseJson<Value>) {
    (StatusCode::OK, ResponseJson(json!({
        "success": true,
        "data": data
    })))
}

fn err_response(msg: &str) -> (StatusCode, ResponseJson<Value>) {
    (StatusCode::BAD_REQUEST, ResponseJson(json!({
        "success": false,
        "error": msg
    })))
}

fn parse_address(addr: &str, name: &str) -> Result<Pubkey, String> {
    // basic length check
    if addr.len() < 32 || addr.len() > 44 {
        return Err(format!("bad {} format", name));
    }
    
    match Pubkey::from_str(addr) {
        Ok(pk) => Ok(pk),
        Err(_) => Err(format!("invalid {}", name)),
    }
}

fn check_amount(amt: u64, field: &str) -> Result<(), String> {
    if amt == 0 {
        return Err(format!("{} must be > 0", field));
    }
    // don't allow crazy large amounts
    if amt > u64::MAX / 2 {
        return Err(format!("{} too big", field));
    }
    Ok(())
}

fn check_decimals(d: u8) -> Result<(), String> {
    if d > 9 {
        return Err("max 9 decimals".to_string());
    }
    Ok(())
}

async fn generate_keypair() -> impl IntoResponse {
    let kp = Keypair::new();
    let secret_b58 = bs58::encode(&kp.to_bytes()).into_string();
    let pubkey_b58 = kp.pubkey().to_string();
    
    let resp = KeypairResp {
        pubkey: pubkey_b58,
        secret: secret_b58,
    };
    
    ok_response(resp)
}

async fn create_token(Json(req): Json<CreateTokenReq>) -> impl IntoResponse {
    let mint_auth = match req.mint_authority {
        Some(ref ma) if !ma.trim().is_empty() => ma.trim(),
        _ => return err_response("need mint authority"),
    };
    
    let mint_addr = match req.mint {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return err_response("need mint"),
    };
    
    let decimals = match req.decimals {
        Some(d) => d,
        None => return err_response("need decimals"),
    };
    
    if let Err(e) = check_decimals(decimals) {
        return err_response(&e);
    }
    
    let mint_authority_pk = match parse_address(mint_auth, "mint authority") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let mint_pk = match parse_address(mint_addr, "mint") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    // can't be same
    if mint_authority_pk == mint_pk {
        return err_response("mint and authority can't match");
    }
    
    let ix = match spl_instruction::initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint_pk,
        &mint_authority_pk,
        None,
        decimals,
    ) {
        Ok(instruction) => instruction,
        Err(e) => return err_response(&format!("failed to build ix: {}", e)),
    };
    
    let accs: Vec<AccInfo> = ix.accounts
        .iter()
        .map(|acc| AccInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let ix_data = general_purpose::STANDARD.encode(&ix.data);
    
    let resp = InstructionResp {
        program_id: ix.program_id.to_string(),
        accounts: accs,
        instruction_data: ix_data,
    };
    
    ok_response(resp)
}

async fn mint_token(Json(req): Json<MintTokenReq>) -> impl IntoResponse {
    let mint_addr = match req.mint {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return err_response("need mint"),
    };
    
    let dest_addr = match req.destination {
        Some(ref d) if !d.trim().is_empty() => d.trim(),
        _ => return err_response("need destination"),
    };
    
    let auth_addr = match req.authority {
        Some(ref a) if !a.trim().is_empty() => a.trim(),
        _ => return err_response("need authority"),
    };
    
    let amt = match req.amount {
        Some(amount) => {
            if let Err(e) = check_amount(amount, "amount") {
                return err_response(&e);
            }
            amount
        },
        None => return err_response("need amount"),
    };
    
    let mint_pk = match parse_address(mint_addr, "mint") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let dest_pk = match parse_address(dest_addr, "destination") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let auth_pk = match parse_address(auth_addr, "authority") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    if dest_pk == mint_pk {
        return err_response("can't mint to mint address");
    }
    
    let ix = match spl_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint_pk,
        &dest_pk,
        &auth_pk,
        &[],
        amt,
    ) {
        Ok(instruction) => instruction,
        Err(e) => return err_response(&format!("failed ix: {}", e)),
    };
    
    let accs: Vec<AccInfo> = ix.accounts
        .iter()
        .map(|acc| AccInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    let ix_data = general_purpose::STANDARD.encode(&ix.data);
    
    let resp = InstructionResp {
        program_id: ix.program_id.to_string(),
        accounts: accs,
        instruction_data: ix_data,
    };
    
    ok_response(resp)
}

async fn sign_message(Json(req): Json<SignMsgReq>) -> impl IntoResponse {
    let msg = match req.message {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return err_response("need message"),
    };
    
    let secret_key = match req.secret {
        Some(ref s) if !s.trim().is_empty() => s.trim(),
        _ => return err_response("need secret"),
    };
    
    // don't allow super long messages
    if msg.len() > 1024 {
        return err_response("message too long");
    }
    
    let secret_bytes = match bs58::decode(secret_key).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return err_response("bad secret format"),
    };
    
    if secret_bytes.len() != 64 {
        return err_response("wrong secret length");
    }
    
    let kp = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(_) => return err_response("invalid secret"),
    };
    
    let sig = kp.sign_message(msg.as_bytes());
    let sig_b64 = general_purpose::STANDARD.encode(sig.as_ref());
    
    let resp = SignResp {
        signature: sig_b64,
        public_key: kp.pubkey().to_string(),
        message: msg.to_string(),
    };
    
    ok_response(resp)
}

async fn verify_message(Json(req): Json<VerifyMsgReq>) -> impl IntoResponse {
    let msg = match req.message {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return err_response("need message"),
    };
    
    let sig_str = match req.signature {
        Some(ref s) if !s.trim().is_empty() => s.trim(),
        _ => return err_response("need signature"),
    };
    
    let pk_str = match req.pubkey {
        Some(ref p) if !p.trim().is_empty() => p.trim(),
        _ => return err_response("need pubkey"),
    };
    
    if msg.len() > 1024 {
        return err_response("message too long");
    }
    
    let pk = match parse_address(pk_str, "pubkey") {
        Ok(pubkey) => pubkey,
        Err(e) => return err_response(&e),
    };
    
    let sig_bytes = match general_purpose::STANDARD.decode(sig_str) {
        Ok(bytes) => bytes,
        Err(_) => return err_response("bad signature format"),
    };
    
    if sig_bytes.len() != 64 {
        return err_response("wrong signature length");
    }
    
    let sig = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(signature) => signature,
        Err(_) => return err_response("invalid signature"),
    };
    
    let valid = sig.verify(&pk.to_bytes(), msg.as_bytes());
    
    let resp = VerifyResp {
        valid: valid,
        message: msg.to_string(),
        pubkey: pk_str.to_string(),
    };
    
    ok_response(resp)
}

async fn send_sol(Json(req): Json<SendSolReq>) -> impl IntoResponse {
    let from_addr = match req.from {
        Some(ref f) if !f.trim().is_empty() => f.trim(),
        _ => return err_response("need from address"),
    };
    
    let to_addr = match req.to {
        Some(ref t) if !t.trim().is_empty() => t.trim(),
        _ => return err_response("need to address"),
    };
    
    let lamports = match req.lamports {
        Some(l) => {
            if let Err(e) = check_amount(l, "lamports") {
                return err_response(&e);
            }
            l
        },
        None => return err_response("need lamports"),
    };
    
    let from_pk = match parse_address(from_addr, "from") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let to_pk = match parse_address(to_addr, "to") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    if from_pk == to_pk {
        return err_response("can't send to self");
    }
    
    let ix = system_instruction::transfer(&from_pk, &to_pk, lamports);
    
    let accs: Vec<String> = ix.accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();
    
    let ix_data = general_purpose::STANDARD.encode(&ix.data);
    
    let resp = SolTransferResp {
        program_id: ix.program_id.to_string(),
        accounts: accs,
        instruction_data: ix_data,
    };
    
    ok_response(resp)
}

async fn send_token(Json(req): Json<SendTokenReq>) -> impl IntoResponse {
    let dest = match req.destination {
        Some(ref dest_addr) if !dest_addr.trim().is_empty() => dest_addr.trim(),
        _ => return err_response("need destination"),
    };
    
    let mint_addr = match req.mint {
        Some(ref m) if !m.trim().is_empty() => m.trim(),
        _ => return err_response("need mint"),
    };
    
    let owner_addr = match req.owner {
        Some(ref o) if !o.trim().is_empty() => o.trim(),
        _ => return err_response("need owner"),
    };
    
    let amt = match req.amount {
        Some(amount) => {
            if let Err(e) = check_amount(amount, "amount") {
                return err_response(&e);
            }
            amount
        },
        None => return err_response("need amount"),
    };
    
    let dest_pk = match parse_address(dest, "destination") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let mint_pk = match parse_address(mint_addr, "mint") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let owner_pk = match parse_address(owner_addr, "owner") {
        Ok(pk) => pk,
        Err(e) => return err_response(&e),
    };
    
    let source_pk = spl_associated_token_account::get_associated_token_address(&owner_pk, &mint_pk);
    
    // check not same account
    if source_pk == dest_pk {
        return err_response("can't send to same account");
    }
    
    let ix = match spl_instruction::transfer(
        &TOKEN_PROGRAM_ID,
        &source_pk,
        &dest_pk,
        &owner_pk,
        &[],
        amt,
    ) {
        Ok(instruction) => instruction,
        Err(e) => return err_response(&format!("failed ix: {}", e)),
    };
    
    let accs: Vec<TokenAccInfo> = ix.accounts
        .iter()
        .map(|acc| TokenAccInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();
    
    let ix_data = general_purpose::STANDARD.encode(&ix.data);
    
    let resp = TokenTransferResp {
        program_id: ix.program_id.to_string(),
        accounts: accs,
        instruction_data: ix_data,
    };
    
    ok_response(resp)
}

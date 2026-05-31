// AlgoVoi webhook-verifier cross-validation — Rust implementation
// Usage: cargo run -- ../../vectors
//
// Cargo.toml dependencies: serde, serde_json, hmac, sha2, hex

use std::env;
use std::fs;
use std::path::Path;

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Sha256, Sha384};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

const HKDF_SALT: &[u8] = b"algovoi-webhook-v2-pqc";
const HKDF_INFO: &[u8] = b"hmac-sha384-outbound";

/// HKDF-SHA256 Extract + Expand (RFC 5869)
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // Extract
    let mut mac = HmacSha256::new_from_slice(salt).unwrap();
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Expand
    let mut okm = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < length {
        let mut mac = HmacSha256::new_from_slice(&prk).unwrap();
        mac.update(&prev);
        mac.update(info);
        mac.update(&[counter]);
        let t = mac.finalize().into_bytes();
        okm.extend_from_slice(&t);
        prev = t.to_vec();
        counter += 1;
    }
    okm.truncate(length);
    okm
}

fn compute_sigs(secret: &str, ts: i64, body: &[u8]) -> (String, String) {
    let secret_bytes = secret.as_bytes();
    let ts_prefix = format!("{}.", ts);
    let signed: Vec<u8> = [ts_prefix.as_bytes(), body].concat();

    // v1: HMAC-SHA256
    let mut mac1 = HmacSha256::new_from_slice(secret_bytes).unwrap();
    mac1.update(&signed);
    let v1 = hex::encode(mac1.finalize().into_bytes());

    // v2_key: HKDF-SHA256
    let v2_key = hkdf_sha256(secret_bytes, HKDF_SALT, HKDF_INFO, 48);

    // v2: HMAC-SHA384
    let mut mac2 = HmacSha384::new_from_slice(&v2_key).unwrap();
    mac2.update(&signed);
    let v2 = hex::encode(mac2.finalize().into_bytes());

    (v1, v2)
}

#[derive(Deserialize)]
struct Fixture {
    #[serde(default)]
    secret: String,
    #[serde(default)]
    timestamp: i64,
    #[serde(default)]
    body: String,
    #[serde(default)]
    signature_header: String,
    #[serde(default)]
    expected: String,
    #[serde(default)]
    error_code: String,
    #[serde(default)]
    tolerance: i64,
    #[serde(default)]
    fake_now: i64,
}

fn verify(f: &Fixture) -> String {
    let hdr = f.signature_header.trim();
    if hdr.is_empty() {
        return "MISSING_SIGNATURE".into();
    }

    // Parse header: t=<ts>,v1=<64hex>[,v2=<96hex>]
    let re = regex::Regex::new(
        r"^t=(\d+),v1=([0-9a-f]{64})(?:,v2=([0-9a-f]{96}))?$"
    ).unwrap();

    let caps = match re.captures(hdr) {
        Some(c) => c,
        None => return "MALFORMED_SIGNATURE".into(),
    };

    let ts: i64 = caps[1].parse().unwrap_or(0);
    let received_v1 = &caps[2];
    let received_v2 = caps.get(3).map(|m| m.as_str());

    // Staleness check
    if f.fake_now > 0 && f.tolerance > 0 {
        let age = (ts - f.fake_now).abs();
        if age > f.tolerance {
            return "STALE_SIGNATURE".into();
        }
    }

    let body = f.body.as_bytes();
    let (expected_v1, expected_v2) = compute_sigs(&f.secret, f.timestamp, body);

    let v1_ok = received_v1 == expected_v1;
    let v2_ok = match received_v2 {
        Some(rv2) => rv2 == expected_v2,
        None => true,
    };

    if !v1_ok || !v2_ok {
        return "INVALID_SIGNATURE".into();
    }

    // JSON parse
    let event: serde_json::Value = match serde_json::from_str(&f.body) {
        Ok(v) => v,
        Err(_) => return "INVALID_PAYLOAD".into(),
    };

    if !event.is_object() {
        return "INVALID_PAYLOAD".into();
    }

    let event_type = event["type"].as_str().unwrap_or("");
    if event_type != "payment.confirmed" {
        return "UNKNOWN_EVENT_TYPE".into();
    }

    "ok".into()
}

fn run_dir(dir: &Path) -> (usize, usize) {
    let mut pass = 0;
    let mut total = 0;

    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        let data = fs::read_to_string(&path).unwrap();
        let f: Fixture = serde_json::from_str(&data).unwrap();
        let name = path.file_name().unwrap().to_string_lossy();

        let result = verify(&f);
        let want = if f.expected == "ok" { "ok".to_string() } else { f.error_code.clone() };

        total += 1;
        if result == want {
            pass += 1;
            println!("  PASS  {}", name);
        } else {
            println!("  FAIL  {}  (want={} got={})", name, want, result);
        }
    }
    (pass, total)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let vectors_root = args.get(1).map(|s| s.as_str()).unwrap_or("../../vectors");

    println!("AlgoVoi webhook-verifier — Rust cross-validation");
    println!();

    println!("valid/");
    let (vp, vt) = run_dir(&Path::new(vectors_root).join("valid"));

    println!("invalid/");
    let (ip, it) = run_dir(&Path::new(vectors_root).join("invalid"));

    let total = vt + it;
    let pass = vp + ip;
    println!("\nResult: {}/{}", pass, total);
    if pass != total {
        std::process::exit(1);
    }
}

use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// URL-safe random token with a recognisable prefix, e.g. `lpm_...`.
pub fn random_token(prefix: &str) -> String {
    let b = random_bytes(32);
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn sha256_b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

/// Keyed hash used to store tokens and codes; plaintext is never persisted.
pub fn token_hash(pepper: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("hmac accepts any key length");
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Short human-comparable pairing code, e.g. `K7QF-2M9D` (no ambiguous characters).
pub fn pairing_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let bytes = random_bytes(8);
    let chars: String = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// Canonical JSON digest (keys sorted) for binding approvals to exact arguments.
pub fn json_digest(value: &serde_json::Value) -> String {
    fn canon(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), canon(&m[k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(canon).collect()),
            other => other.clone(),
        }
    }
    let bytes = serde_json::to_vec(&canon(value)).unwrap_or_default();
    sha256_hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_independent() {
        let a = serde_json::json!({"a": 1, "b": {"x": 1, "y": 2}});
        let b = serde_json::json!({"b": {"y": 2, "x": 1}, "a": 1});
        assert_eq!(json_digest(&a), json_digest(&b));
        assert_ne!(json_digest(&a), json_digest(&serde_json::json!({"a": 2})));
    }

    #[test]
    fn tokens_and_codes() {
        let t = random_token("lpm");
        assert!(t.starts_with("lpm_") && t.len() > 40);
        let p = pairing_code();
        assert_eq!(p.len(), 9);
        let h1 = token_hash(b"pepper", &t);
        assert_eq!(h1, token_hash(b"pepper", &t));
        assert_ne!(h1, token_hash(b"other", &t));
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
    }
}

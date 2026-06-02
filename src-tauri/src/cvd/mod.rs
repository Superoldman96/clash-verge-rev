//! CVD (Clash Verge Device-binding) protocol — client side.
//! See docs/cvd-server-integration.md

/// HPKE `info` string, fixed per spec §3.
const INFO: &[u8] = b"cvd-v1";

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable as _, OpModeR,
    aead::{AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    single_shot_open,
};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use zeroize::Zeroizing;

/// HPKE KEM fixed per spec §3: DHKEM(X25519, HKDF-SHA256).
type Kem = X25519HkdfSha256;

/// AEAD suite ids per RFC 9180 §7.3 / spec §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvdAead {
    Aes256Gcm = 0x0002,
    ChaCha20Poly1305 = 0x0003,
}

impl CvdAead {
    /// Parse the decimal value of `X-CVD-AEAD` (`"2"` / `"3"`).
    pub fn from_header_value(v: &str) -> Option<Self> {
        match v.trim() {
            "2" => Some(Self::Aes256Gcm),
            "3" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Generate an X25519 static keypair. Returns (private 32B zeroizing, public 32B).
pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    (Zeroizing::new(secret.to_bytes()), public.to_bytes())
}

/// HPKE Base-mode open. `payload = enc[32] || ciphertext`, `info = b"cvd-v1"`.
pub fn hpke_open(secret: &[u8; 32], aead: CvdAead, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 48 {
        bail!("cvd payload too short ({} bytes)", payload.len());
    }
    let (enc_bytes, ciphertext) = payload.split_at(32);
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|e| anyhow!("bad cvd private key: {e}"))?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc_bytes).map_err(|e| anyhow!("bad cvd enc key: {e}"))?;
    let pt = match aead {
        CvdAead::ChaCha20Poly1305 => {
            single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeR::Base, &sk, &enc, INFO, ciphertext, b"")
        }
        CvdAead::Aes256Gcm => {
            single_shot_open::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &sk, &enc, INFO, ciphertext, b"")
        }
    }
    .map_err(|e| anyhow!("cvd decryption failed: {e}"))?;
    Ok(pt)
}

/// Build the opportunistic CVD request headers (spec §5.1). Does not touch URL/query.
pub fn request_headers(public: &[u8; 32]) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("X-CVD-Ver", HeaderValue::from_static("1"));
    h.insert("X-CVD-AEAD", HeaderValue::from_static("3")); // declared preference: ChaCha20-Poly1305
    let pub_b64 = URL_SAFE_NO_PAD.encode(public);
    if let Ok(v) = HeaderValue::from_str(&pub_b64) {
        h.insert("X-CVD-Pub", v);
    }
    h
}

/// Outcome of inspecting a subscription response under CVD.
#[derive(Debug)]
pub enum CvdResponse {
    /// `payload = enc[32] || ciphertext`, already base64url-decoded.
    Encrypted { aead: CvdAead, payload: Vec<u8> },
    /// No `X-CVD-Encrypted` header — unmodified airport / token without CVD policy.
    Plaintext,
    /// 403 + `X-CVD-Error: device_limit_exceeded`.
    DeviceLimit,
    /// Other non-2xx, or `X-CVD-Encrypted: 1` with malformed body. Never falls back to plaintext.
    Error(String),
}

/// Decide how to handle a subscription response. `body` is the (text-decoded) HTTP body;
/// for encrypted responses it is base64url(enc || ciphertext).
pub fn parse_response(status: StatusCode, headers: &HeaderMap, body: &str) -> CvdResponse {
    // 1. Device-limit takes precedence (it is a 403, checked before any success check).
    if status == StatusCode::FORBIDDEN
        && headers
            .get("X-CVD-Error")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim() == "device_limit_exceeded")
            .unwrap_or(false)
    {
        return CvdResponse::DeviceLimit;
    }

    // 2. Per spec §5.4, any other non-2xx is an error (even if it carries encrypted headers).
    if !status.is_success() {
        return CvdResponse::Error(format!("failed to fetch remote profile with status {status}"));
    }

    // 3. Status is 2xx — check for encrypted response.
    let is_encrypted = headers
        .get("X-CVD-Encrypted")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == "1")
        .unwrap_or(false);

    if is_encrypted {
        let aead = match headers
            .get("X-CVD-AEAD")
            .and_then(|v| v.to_str().ok())
            .and_then(CvdAead::from_header_value)
        {
            Some(a) => a,
            None => return CvdResponse::Error("missing or invalid X-CVD-AEAD on encrypted response".into()),
        };
        let payload = match URL_SAFE_NO_PAD.decode(body.trim().as_bytes()) {
            Ok(p) => p,
            Err(e) => return CvdResponse::Error(format!("cvd body is not valid base64url: {e}")),
        };
        if payload.len() < 48 {
            return CvdResponse::Error(format!("cvd payload too short ({} bytes)", payload.len()));
        }
        return CvdResponse::Encrypted { aead, payload };
    }

    // 4. Success, no encryption headers — plaintext.
    CvdResponse::Plaintext
}

const KEYCHAIN_SERVICE: &str = "clash-verge-rev";

fn keychain_user(profile_uid: &str) -> String {
    format!("cvd/{profile_uid}")
}

/// Delete the keychain private key for `profile_uid`. Missing entry is treated as success.
pub fn delete_key(profile_uid: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &keychain_user(profile_uid))
        .map_err(|e| anyhow!("keychain unavailable: {e}"))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow!("failed to delete cvd key: {e}")),
    }
}

/// An X25519 device keypair held in memory. The private key is written to the OS keychain only via
/// [`persist`], which the caller invokes *after* the owning profile has been saved — so a fetch or
/// save that fails never leaves an orphaned key (or the server slot it would register). The public
/// key is cached (non-secret) in `profiles.yaml` so later refreshes never need to touch the keychain.
///
/// [`persist`]: DeviceKey::persist
pub struct DeviceKey {
    uid: String,
    public: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl DeviceKey {
    /// Generate a fresh keypair in memory. Does not touch the keychain.
    pub fn generate(uid: &str) -> Self {
        let (secret, public) = generate_keypair();
        Self {
            uid: uid.to_owned(),
            public,
            secret,
        }
    }

    /// The 32-byte public key (sent in the `X-CVD-Pub` header).
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// base64url(no-pad) of the public key, for caching in `profiles.yaml`.
    pub fn public_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public)
    }

    /// Write the private key to the OS keychain (`cvd/<uid>`). Call this only after the owning
    /// profile is durably saved, so a failed create never persists a key.
    pub fn persist(&self) -> Result<()> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &keychain_user(&self.uid))
            .map_err(|e| anyhow!("keychain unavailable: {e}"))?;
        entry
            .set_password(&URL_SAFE_NO_PAD.encode(*self.secret))
            .map_err(|e| anyhow!("failed to store cvd key: {e}"))
    }

    /// HPKE-open a payload with this in-memory secret (used on the create path, where the key is not
    /// yet in the keychain). Returns plaintext YAML.
    pub fn open(&self, aead: CvdAead, payload: &[u8]) -> Result<String> {
        open_with_secret(&self.secret, aead, payload)
    }
}

/// Parse a cached base64url public key (from `profiles.yaml`) into 32 raw bytes.
pub fn public_from_b64(b64: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(b64.trim()).ok()?;
    bytes.as_slice().try_into().ok()
}

/// Load the private key for `profile_uid` from the keychain. `Ok(None)` means there is no entry
/// (e.g. the profile was restored to a new device, or its key was never persisted) — the caller uses
/// that to trigger re-registration. Used on the refresh path, lazily, only when a ciphertext actually
/// needs decrypting, so plain (non-CVD) refreshes never touch the keychain.
pub fn load_device_secret(profile_uid: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &keychain_user(profile_uid))
        .map_err(|e| anyhow!("keychain unavailable: {e}"))?;
    match entry.get_password() {
        Ok(b64) => {
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(b64.trim())
                    .map_err(|e| anyhow!("corrupt stored cvd key: {e}"))?,
            );
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("stored cvd key is not 32 bytes"))?;
            Ok(Some(Zeroizing::new(arr)))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("keychain read failed: {e}")),
    }
}

/// HPKE-open a payload with a raw 32-byte secret. Returns plaintext YAML.
pub fn open_with_secret(secret: &[u8; 32], aead: CvdAead, payload: &[u8]) -> Result<String> {
    let pt = hpke_open(secret, aead, payload)?;
    String::from_utf8(pt).map_err(|e| anyhow!("decrypted cvd payload is not valid UTF-8: {e}"))
}

/// Marker error: a refresh received ciphertext but the profile's private key is absent from the
/// keychain (the device was restored, or an earlier `persist` failed). The caller detects this via
/// `downcast_ref` and re-registers a fresh key instead of retrying — this response was sealed to the
/// lost key and can never be decrypted.
#[derive(Debug)]
pub struct CvdKeyMissing;

impl std::fmt::Display for CvdKeyMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cvd private key missing")
    }
}

impl std::error::Error for CvdKeyMissing {}

/// How a single remote fetch should use CVD. Chosen by the caller, who owns the device-key
/// lifecycle (generate → use → persist-after-save), so `from_url` never writes to the keychain.
#[derive(Clone, Copy)]
pub enum CvdMode<'a> {
    /// Brand-new profile (or the first key for a pre-CVD one): use this in-memory key for the
    /// header and to decrypt. The caller calls [`DeviceKey::persist`] only after the profile is
    /// saved, so a failed fetch/save never leaves an orphaned key or server slot.
    New(&'a DeviceKey),
    /// Refreshing a profile that already cached a public key: advertise the cached key; read the
    /// private key from the keychain lazily, only to decrypt an actual ciphertext.
    Existing { public: [u8; 32] },
    /// No CVD this fetch (keychain-free) — e.g. a silent auto-update of a profile that has no
    /// cached key yet.
    Disabled,
}

impl CvdMode<'_> {
    /// The public key to advertise in the request header, if any.
    pub const fn header_public(&self) -> Option<[u8; 32]> {
        match self {
            Self::New(k) => Some(*k.public()),
            Self::Existing { public } => Some(*public),
            Self::Disabled => None,
        }
    }

    /// The base64url public key to cache on the built item, if any.
    pub fn cached_public_b64(&self) -> Option<std::string::String> {
        match self {
            Self::New(k) => Some(k.public_b64()),
            Self::Existing { public } => Some(URL_SAFE_NO_PAD.encode(public)),
            Self::Disabled => None,
        }
    }

    /// Whether CVD is active for this fetch (i.e. a header was sent).
    pub const fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Test-only HPKE seal, mirrors the server's encryption (spec §5.5).
#[cfg(test)]
#[allow(clippy::expect_used)]
pub fn hpke_seal(public: &[u8; 32], aead: CvdAead, plaintext: &[u8]) -> Vec<u8> {
    use hpke::{OpModeS, Serializable as _, single_shot_seal};
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(public).expect("valid pubkey");
    let mut rng = rand_core::OsRng;
    let (enc, ct) = match aead {
        CvdAead::ChaCha20Poly1305 => single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
            &OpModeS::Base,
            &pk,
            INFO,
            plaintext,
            b"",
            &mut rng,
        ),
        CvdAead::Aes256Gcm => {
            single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(&OpModeS::Base, &pk, INFO, plaintext, b"", &mut rng)
        }
    }
    .expect("seal ok");
    let mut payload = enc.to_bytes().to_vec();
    payload.extend_from_slice(&ct);
    payload
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::{Once, OnceLock};

    #[test]
    fn hpke_roundtrip_chacha() {
        let (sk, pk) = generate_keypair();
        let plaintext = b"proxies:\n  - {name: a}\n";
        let payload = hpke_seal(&pk, CvdAead::ChaCha20Poly1305, plaintext);
        let out = hpke_open(&sk, CvdAead::ChaCha20Poly1305, &payload).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn hpke_roundtrip_aes() {
        let (sk, pk) = generate_keypair();
        let plaintext = b"hello-cvd";
        let payload = hpke_seal(&pk, CvdAead::Aes256Gcm, plaintext);
        let out = hpke_open(&sk, CvdAead::Aes256Gcm, &payload).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn hpke_open_rejects_short_payload() {
        let (sk, _pk) = generate_keypair();
        let err = hpke_open(&sk, CvdAead::ChaCha20Poly1305, &[0u8; 10]);
        assert!(err.is_err());
    }

    #[test]
    fn hpke_open_wrong_key_fails() {
        let (_sk1, pk1) = generate_keypair();
        let (sk2, _pk2) = generate_keypair();
        let payload = hpke_seal(&pk1, CvdAead::ChaCha20Poly1305, b"secret");
        assert!(hpke_open(&sk2, CvdAead::ChaCha20Poly1305, &payload).is_err());
    }

    #[test]
    fn request_headers_format() {
        let pk = [7u8; 32];
        let h = request_headers(&pk);
        assert_eq!(h.get("X-CVD-Ver").unwrap(), "1");
        assert_eq!(h.get("X-CVD-AEAD").unwrap(), "3");
        let pub_hdr = h.get("X-CVD-Pub").unwrap().to_str().unwrap();
        assert_eq!(pub_hdr.len(), 43);
        assert!(!pub_hdr.contains('=') && !pub_hdr.contains('+') && !pub_hdr.contains('/'));
    }

    fn hdrs(pairs: &[(&str, &str)]) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                reqwest::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn parse_plaintext_when_no_cvd_header() {
        let r = parse_response(StatusCode::OK, &hdrs(&[]), "proxies: []");
        assert!(matches!(r, CvdResponse::Plaintext));
    }

    #[test]
    fn parse_device_limit() {
        let h = hdrs(&[("X-CVD-Error", "device_limit_exceeded")]);
        let r = parse_response(StatusCode::FORBIDDEN, &h, "");
        assert!(matches!(r, CvdResponse::DeviceLimit));
    }

    #[test]
    fn parse_encrypted_ok() {
        let (sk, pk) = generate_keypair();
        let payload = hpke_seal(&pk, CvdAead::ChaCha20Poly1305, b"proxies: []");
        let body = URL_SAFE_NO_PAD.encode(&payload);
        let h = hdrs(&[("X-CVD-Encrypted", "1"), ("X-CVD-AEAD", "3")]);
        match parse_response(StatusCode::OK, &h, &body) {
            CvdResponse::Encrypted { aead, payload: p } => {
                assert_eq!(aead, CvdAead::ChaCha20Poly1305);
                assert_eq!(hpke_open(&sk, aead, &p).unwrap(), b"proxies: []");
            }
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn parse_encrypted_bad_aead_is_error() {
        let h = hdrs(&[("X-CVD-Encrypted", "1"), ("X-CVD-AEAD", "9")]);
        let r = parse_response(StatusCode::OK, &h, "AAAA");
        assert!(matches!(r, CvdResponse::Error(_)));
    }

    #[test]
    fn parse_encrypted_short_body_is_error() {
        let body = URL_SAFE_NO_PAD.encode([0u8; 10]);
        let h = hdrs(&[("X-CVD-Encrypted", "1"), ("X-CVD-AEAD", "3")]);
        let r = parse_response(StatusCode::OK, &h, &body);
        assert!(matches!(r, CvdResponse::Error(_)));
    }

    #[test]
    fn parse_non_success_without_cvd_is_error() {
        let r = parse_response(StatusCode::INTERNAL_SERVER_ERROR, &hdrs(&[]), "");
        assert!(matches!(r, CvdResponse::Error(_)));
    }

    #[test]
    fn parse_encrypted_non_success_is_error() {
        let h = hdrs(&[("X-CVD-Encrypted", "1"), ("X-CVD-AEAD", "3")]);
        let r = parse_response(StatusCode::SERVICE_UNAVAILABLE, &h, "AAAA");
        assert!(matches!(r, CvdResponse::Error(_)));
    }

    // keyring 3.6.3's built-in `mock` store keeps state in the `Entry` instance only
    // (`CredentialPersistence::EntryOnly`), so two `Entry::new` calls for the same
    // service/user do NOT share data — which defeats the cross-call idempotency this test
    // needs. We supply a tiny shared in-memory keystore keyed by service+user instead.
    fn store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
        static STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    #[derive(Debug)]
    struct SharedCredential {
        key: String,
    }

    impl keyring::credential::CredentialApi for SharedCredential {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            store().lock().insert(self.key.clone(), secret.to_vec());
            Ok(())
        }
        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            store().lock().get(&self.key).cloned().ok_or(keyring::Error::NoEntry)
        }
        fn delete_credential(&self) -> keyring::Result<()> {
            let removed = store().lock().remove(&self.key);
            match removed {
                Some(_) => Ok(()),
                None => Err(keyring::Error::NoEntry),
            }
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct SharedBuilder;
    impl keyring::credential::CredentialBuilderApi for SharedBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<keyring::credential::Credential>> {
            Ok(Box::new(SharedCredential {
                key: format!("{service}\u{0}{user}"),
            }))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    static MOCK_INIT: Once = Once::new();
    fn init_mock_keyring() {
        MOCK_INIT.call_once(|| {
            keyring::set_default_credential_builder(Box::new(SharedBuilder));
        });
    }

    #[test]
    fn device_key_public_b64_is_43_chars() {
        let k = DeviceKey::generate("Rdk01");
        let b64 = k.public_b64();
        assert_eq!(b64.len(), 43);
        assert!(!b64.contains('=') && !b64.contains('+') && !b64.contains('/'));
    }

    #[test]
    fn public_from_b64_roundtrips_device_public() {
        let k = DeviceKey::generate("Rdk02");
        let parsed = public_from_b64(&k.public_b64()).expect("parse cached pubkey");
        assert_eq!(&parsed, k.public());
    }

    #[test]
    fn device_key_open_decrypts_payload_sealed_to_its_public() {
        let k = DeviceKey::generate("Rdk03");
        let payload = hpke_seal(k.public(), CvdAead::ChaCha20Poly1305, b"proxies: []\n");
        assert_eq!(k.open(CvdAead::ChaCha20Poly1305, &payload).unwrap(), "proxies: []\n");
    }

    #[test]
    fn persist_then_load_device_secret_decrypts() {
        init_mock_keyring();
        let uid = "Rdkpersist01";
        let k = DeviceKey::generate(uid);
        let pubk = *k.public();
        k.persist().unwrap();
        let secret = load_device_secret(uid).unwrap().expect("secret present after persist");
        let payload = hpke_seal(&pubk, CvdAead::Aes256Gcm, b"hello");
        assert_eq!(
            open_with_secret(&secret, CvdAead::Aes256Gcm, &payload).unwrap(),
            "hello"
        );
        delete_key(uid).unwrap();
    }

    #[test]
    fn load_device_secret_is_none_when_absent() {
        init_mock_keyring();
        assert!(load_device_secret("Rdkabsent01").unwrap().is_none());
    }

    #[test]
    fn cvd_key_missing_survives_anyhow_downcast() {
        // The refresh recovery relies on detecting this exact type through anyhow::Error.
        let err = anyhow!(CvdKeyMissing);
        assert!(err.downcast_ref::<CvdKeyMissing>().is_some());
    }
}

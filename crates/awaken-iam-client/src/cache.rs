//! Shared client-side credential cache: login-once, reuse-until-expiry.
//!
//! Credentials are persisted at `${XDG_CONFIG_HOME:-~/.config}/awaken/credentials.json`
//! with mode 0600, keyed by the server `base_url`. A credential is only
//! returned from [`CredentialCache::load`] when it has not yet expired;
//! `login` writes a fresh entry, `logout` clears it.
//!
//! The cache supports both credential families:
//! - `sk-awaken-` prefixed long-lived API tokens (no natural expiry — callers
//!   supply an explicit `expires_at` representing the rotation deadline or a
//!   far-future sentinel).
//! - Cloud EdDSA JWTs that already carry an `exp` claim (convert to Unix
//!   seconds and pass as `expires_at`).
//!
//! Secrets are held in [`RedactedString`], which suppresses the value in
//! `Debug` and `Display` output. Credentials are written as **plaintext JSON**
//! to disk; confidentiality relies solely on the 0600 file-system permission.
//! No at-rest encryption is implemented. Protect the file through OS-level
//! controls (e.g. encrypted home directory or disk encryption).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use awaken_iam_contract::PrincipalRef;
use serde::{Deserialize, Serialize};

// ── RedactedString ──────────────────────────────────────────────────────────

/// A secret string that never leaks its value through `Debug` or `Display`.
///
/// Use [`RedactedString::expose`] only when the raw value must be transmitted
/// (e.g. as an `Authorization: Bearer` header).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactedString(String);

impl RedactedString {
    /// Wrap a secret.
    pub fn new(s: impl Into<String>) -> Self {
        RedactedString(s.into())
    }

    /// Borrow the raw secret value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Display for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

// ── Credential ───────────────────────────────────────────────────────────────

/// A bearer credential that can be attached to outgoing requests.
///
/// Mirrors `awaken-credential::Credential::Bearer` so that product CLIs
/// consuming this cache can feed its output directly into their request layer
/// without an extra conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// `Authorization: Bearer <token>` credential.
    Bearer(RedactedString),
}

impl Credential {
    /// Wrap a raw token string as a `Bearer` credential.
    pub fn bearer(token: impl Into<String>) -> Self {
        Credential::Bearer(RedactedString::new(token))
    }

    /// Borrow the raw token value.
    pub fn expose_token(&self) -> &str {
        match self {
            Credential::Bearer(s) => s.expose(),
        }
    }
}

// ── CachedCredential ─────────────────────────────────────────────────────────

/// A credential entry stored in the cache.
///
/// `expires_at` is a Unix timestamp in seconds. Pass a far-future value (e.g.
/// `u64::MAX`) for long-lived API tokens that have no natural expiry. The
/// cache does **not** enforce rotation; callers are responsible for supplying a
/// sensible deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCredential {
    /// Bearer token value. Never logged or displayed.
    pub token: RedactedString,
    /// Principal this credential authenticates.
    pub principal: PrincipalRef,
    /// Unix timestamp (seconds) at which this credential expires.
    ///
    /// The cache returns `None` from [`CredentialCache::load`] once the clock
    /// passes this value.
    pub expires_at: u64,
}

impl CachedCredential {
    /// True when `expires_at` is strictly in the future.
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at > now
    }

    /// Convert this entry into a [`Credential::Bearer`].
    pub fn to_credential(&self) -> Credential {
        Credential::Bearer(self.token.clone())
    }
}

// ── On-disk format ───────────────────────────────────────────────────────────

/// The JSON object persisted to `credentials.json`.
///
/// Keyed by `base_url`; each value is a [`CachedCredential`].
#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    entries: HashMap<String, CachedCredential>,
}

// ── CredentialCache ──────────────────────────────────────────────────────────

/// Persistent per-server credential cache.
///
/// ```text
/// // Login flow
/// let cred = CachedCredential { token: RedactedString::new(token), principal, expires_at };
/// CredentialCache::open().store(&base_url, cred)?;
///
/// // Subsequent invocations
/// if let Some(cred) = CredentialCache::open().load(&base_url) {
///     // reuse cred.to_credential() — no re-login
/// }
///
/// // Logout
/// CredentialCache::open().clear(&base_url)?;
/// ```
#[derive(Debug, Clone)]
pub struct CredentialCache {
    path: PathBuf,
}

impl CredentialCache {
    /// Return the default cache path.
    ///
    /// Resolves `${XDG_CONFIG_HOME:-~/.config}/awaken/credentials.json`,
    /// falling back to `.config` in the current directory when `HOME` is also
    /// absent.
    pub fn default_path() -> PathBuf {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from(".config"));
        config_home.join("awaken").join("credentials.json")
    }

    /// Open the cache at an explicit path (useful in tests and multi-deployment
    /// CLI configurations).
    pub fn at(path: PathBuf) -> Self {
        CredentialCache { path }
    }

    /// Open the cache at [`Self::default_path`].
    pub fn open() -> Self {
        CredentialCache::at(Self::default_path())
    }

    /// Load the cached credential for `base_url`.
    ///
    /// Returns `None` when no entry exists, the file cannot be read, or the
    /// entry has expired. Stale entries remain on disk until replaced by
    /// [`store`](Self::store) or removed by [`clear`](Self::clear).
    pub fn load(&self, base_url: &str) -> Option<CachedCredential> {
        let file = self.read_file().ok()?;
        let entry = file.entries.get(base_url)?;
        entry.is_valid().then(|| entry.clone())
    }

    /// Persist a credential for `base_url`, replacing any existing entry.
    ///
    /// The file is written with mode 0600 on Unix. On non-Unix platforms the
    /// file is written without an explicit mode; callers should secure the
    /// directory through OS-level means.
    pub fn store(&self, base_url: &str, cred: CachedCredential) -> Result<(), CacheError> {
        let mut file = self.read_file().unwrap_or_default();
        file.entries.insert(base_url.to_owned(), cred);
        self.write_file(&file)
    }

    /// Remove the cached credential for `base_url`, if any.
    pub fn clear(&self, base_url: &str) -> Result<(), CacheError> {
        let mut file = self.read_file().unwrap_or_default();
        if file.entries.remove(base_url).is_none() {
            return Ok(());
        }
        self.write_file(&file)
    }

    fn read_file(&self) -> Result<CacheFile, CacheError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| CacheError::Parse(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CacheFile::default()),
            Err(e) => Err(CacheError::Io(e.to_string())),
        }
    }

    fn write_file(&self, file: &CacheFile) -> Result<(), CacheError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CacheError::Io(e.to_string()))?;
        }
        let json =
            serde_json::to_vec_pretty(file).map_err(|e| CacheError::Serialize(e.to_string()))?;
        write_secret_file(&self.path, &json)
    }
}

/// Write `contents` to `path` with mode 0600 on Unix.
fn write_secret_file(path: &std::path::Path, contents: &[u8]) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| CacheError::Io(e.to_string()))?;
        file.write_all(contents)
            .map_err(|e| CacheError::Io(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents).map_err(|e| CacheError::Io(e.to_string()))
    }
}

// ── CacheError ───────────────────────────────────────────────────────────────

/// Error variants returned by [`CredentialCache`] operations.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// An I/O error (permission denied, directory not creatable, …).
    #[error("credential cache I/O error: {0}")]
    Io(String),
    /// The file exists but could not be deserialized.
    #[error("credential cache parse error: {0}")]
    Parse(String),
    /// The cache state could not be serialized before writing.
    #[error("credential cache serialize error: {0}")]
    Serialize(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use awaken_iam_contract::{AccountId, PrincipalRef};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_cache_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "awaken-cred-cache-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("credentials.json")
    }

    fn make_principal() -> PrincipalRef {
        PrincipalRef::Account {
            account_id: AccountId("acct_test".into()),
        }
    }

    fn make_cred(token: &str, expires_at: u64) -> CachedCredential {
        CachedCredential {
            token: RedactedString::new(token),
            principal: make_principal(),
            expires_at,
        }
    }

    #[test]
    fn redacted_string_hides_secret_in_debug_and_display() {
        let s = RedactedString::new("sk-awaken-verysecret.abc");
        assert!(!format!("{s:?}").contains("sk-awaken"));
        assert!(!format!("{s}").contains("sk-awaken"));
        assert_eq!(s.expose(), "sk-awaken-verysecret.abc");
    }

    #[test]
    fn credential_bearer_exposes_token() {
        let cred = Credential::bearer("sk-awaken-tok.abc");
        assert_eq!(cred.expose_token(), "sk-awaken-tok.abc");
        assert!(!format!("{cred:?}").contains("sk-awaken-tok.abc"));
    }

    #[test]
    fn cached_credential_validity() {
        let far_future = u64::MAX / 2;
        assert!(make_cred("t", far_future).is_valid());
        assert!(!make_cred("t", 0).is_valid());
    }

    #[test]
    fn cached_credential_to_credential() {
        let entry = make_cred("bearer-tok", u64::MAX / 2);
        let cred = entry.to_credential();
        assert_eq!(cred.expose_token(), "bearer-tok");
    }

    #[test]
    fn load_returns_none_on_missing_file() {
        let path = temp_cache_path();
        let cache = CredentialCache::at(path);
        assert!(cache.load("https://iam.example.com").is_none());
    }

    #[test]
    fn store_and_load_roundtrip() {
        let cache = CredentialCache::at(temp_cache_path());
        let url = "https://iam.example.com";
        let entry = make_cred("sk-awaken-test.tok", u64::MAX / 2);

        cache.store(url, entry.clone()).unwrap();
        let loaded = cache.load(url).expect("entry should be present");
        assert_eq!(loaded.token.expose(), entry.token.expose());
        assert_eq!(loaded.expires_at, entry.expires_at);
    }

    #[test]
    fn load_ignores_expired_entries() {
        let cache = CredentialCache::at(temp_cache_path());
        let url = "https://iam.example.com";
        cache.store(url, make_cred("old-tok", 0)).unwrap();
        assert!(
            cache.load(url).is_none(),
            "expired entry must not be returned"
        );
    }

    #[test]
    fn store_replaces_existing_entry() {
        let cache = CredentialCache::at(temp_cache_path());
        let url = "https://iam.example.com";
        cache.store(url, make_cred("tok-a", u64::MAX / 2)).unwrap();
        cache.store(url, make_cred("tok-b", u64::MAX / 2)).unwrap();
        let loaded = cache.load(url).unwrap();
        assert_eq!(loaded.token.expose(), "tok-b");
    }

    #[test]
    fn clear_removes_entry() {
        let cache = CredentialCache::at(temp_cache_path());
        let url = "https://iam.example.com";
        cache.store(url, make_cred("tok", u64::MAX / 2)).unwrap();
        cache.clear(url).unwrap();
        assert!(cache.load(url).is_none());
    }

    #[test]
    fn clear_is_idempotent_on_absent_entry() {
        let cache = CredentialCache::at(temp_cache_path());
        cache.clear("https://iam.example.com").unwrap();
    }

    #[test]
    fn multiple_base_urls_are_independent() {
        let cache = CredentialCache::at(temp_cache_path());
        let url_a = "https://a.example.com";
        let url_b = "https://b.example.com";
        cache
            .store(url_a, make_cred("tok-a", u64::MAX / 2))
            .unwrap();
        cache
            .store(url_b, make_cred("tok-b", u64::MAX / 2))
            .unwrap();
        cache.clear(url_a).unwrap();
        assert!(cache.load(url_a).is_none());
        assert_eq!(cache.load(url_b).unwrap().token.expose(), "tok-b");
    }

    #[cfg(unix)]
    #[test]
    fn credentials_file_has_mode_0600() {
        use std::os::unix::fs::MetadataExt as _;
        let path = temp_cache_path();
        let cache = CredentialCache::at(path.clone());
        cache
            .store("https://iam.example.com", make_cred("tok", u64::MAX / 2))
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600, "credentials.json must be mode 0600");
    }
}

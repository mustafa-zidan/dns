//! Who may use the API, and what they may do with it.
//!
//! Every credential is sent as `Authorization: Bearer <secret>`:
//!
//! - A session token, from signing in with an account in `api.users`.
//! - An API token from `api.tokens`, for scripts and other programs.
//! - `api.token`, the single token of earlier versions, which acts as an admin.
//!
//! Viewers can read everything; admins can also change things. With none of
//! these configured, the API is open to whoever can reach it.
//!
//! Only hashes are kept: Argon2id for passwords, and SHA-256 for tokens and
//! sessions, which are random and long enough that a fast hash is safe.

mod audit;
mod limiter;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;

pub use audit::{AuditLog, Event};
use limiter::Limiter;

use crate::config::ApiConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Can read stats, settings and list status.
    #[default]
    Viewer,
    /// Can also change settings, clear the cache and see the audit log.
    Admin,
}

impl FromStr for Role {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "viewer" => Ok(Self::Viewer),
            "admin" => Ok(Self::Admin),
            _ => Err(format!("{text:?} is not a role; use viewer or admin")),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Viewer => "viewer",
            Self::Admin => "admin",
        })
    }
}

/// Who made a request.
#[derive(Debug, Clone)]
pub struct Principal {
    pub name: Arc<str>,
    pub role: Role,
    pub via: Via,
}

/// How a request was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// A session from signing in with a password.
    Session,
    /// An API token.
    Token,
    /// Nothing: the API needs no credentials.
    Open,
}

pub enum LoginError {
    /// `api.users` is empty.
    NoAccounts,
    /// The name or the password is wrong. Which one is not revealed.
    Invalid,
    /// Too many failed attempts for this account or address.
    Limited(Duration),
}

pub struct Login {
    pub token: String,
    pub principal: Principal,
    /// The longest the session can last, if it is kept in use.
    pub expires_in: Duration,
}

type Digest = [u8; 32];

/// Session tokens start with this, and API tokens with [`TOKEN_PREFIX`], so
/// people and secret scanners can tell them apart.
const SESSION_PREFIX: &str = "hds_";
const TOKEN_PREFIX: &str = "hdt_";
const MAX_SESSIONS: usize = 1024;
/// Longer passwords are refused without being hashed.
const MAX_PASSWORD_BYTES: usize = 1024;
/// Password checks run at once. Each takes tens of milliseconds of CPU, which
/// would otherwise be taken from answering queries.
const CONCURRENT_CHECKS: usize = 2;
const LIMIT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failed sign-ins allowed per account in each window.
const ACCOUNT_FAILURES: u32 = 10;
/// Failed sign-ins allowed per client address in each window. Higher than
/// per account, because one address can be a whole household, or a proxy.
const ADDRESS_FAILURES: u32 = 30;
const TRACKED_ADDRESSES: usize = 4096;

pub struct Auth {
    accounts: HashMap<String, Account>,
    tokens: HashMap<Digest, Grant>,
    sessions: Mutex<HashMap<Digest, Session>>,
    session_idle: Duration,
    session_max: Duration,
    by_account: Limiter<String>,
    by_address: Limiter<IpAddr>,
    checks: Semaphore,
    /// Checked for unknown names, so they take as long as known ones.
    decoy_hash: String,
    audit: AuditLog,
}

struct Account {
    password_hash: String,
    role: Role,
}

#[derive(Clone)]
struct Grant {
    name: Arc<str>,
    role: Role,
}

impl Grant {
    fn principal(&self, via: Via) -> Principal {
        Principal {
            name: Arc::clone(&self.name),
            role: self.role,
            via,
        }
    }
}

struct Session {
    grant: Grant,
    started: Instant,
    last_used: Instant,
}

impl Auth {
    /// Takes `api.token`, `api.users` and `api.tokens`, already checked by
    /// [`crate::config::Config::parse`].
    pub fn new(config: &ApiConfig) -> Result<Self> {
        let mut tokens = HashMap::new();
        if let Some(token) = &config.token {
            let grant = Grant {
                name: "api.token".into(),
                role: Role::Admin,
            };
            tokens.insert(digest(token), grant);
        }
        for token in &config.tokens {
            let hash = parse_token_hash(&token.hash)
                .with_context(|| format!("api.tokens: {:?}", token.name))?;
            let grant = Grant {
                name: token.name.as_str().into(),
                role: token.role,
            };
            tokens.insert(hash, grant);
        }
        let accounts = config
            .users
            .iter()
            .map(|user| {
                let account = Account {
                    password_hash: user.password_hash.clone(),
                    role: user.role,
                };
                (user.name.clone(), account)
            })
            .collect::<HashMap<_, _>>();
        let decoy_hash = if accounts.is_empty() {
            String::new()
        } else {
            hash_password("decoy")?
        };
        Ok(Self {
            accounts,
            tokens,
            sessions: Mutex::default(),
            session_idle: Duration::from_secs(config.session_idle_secs),
            session_max: Duration::from_secs(config.session_max_secs),
            by_account: Limiter::new(ACCOUNT_FAILURES, LIMIT_WINDOW, config.users.len().max(1)),
            by_address: Limiter::new(ADDRESS_FAILURES, LIMIT_WINDOW, TRACKED_ADDRESSES),
            checks: Semaphore::new(CONCURRENT_CHECKS),
            decoy_hash,
            audit: AuditLog::default(),
        })
    }

    /// Whether requests need credentials.
    pub fn required(&self) -> bool {
        !self.accounts.is_empty() || !self.tokens.is_empty()
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Who a bearer secret belongs to, or `None` if it is unknown or its
    /// session has ended.
    pub fn authenticate(&self, bearer: Option<&str>) -> Option<Principal> {
        if !self.required() {
            return Some(Principal {
                name: "anonymous".into(),
                role: Role::Admin,
                via: Via::Open,
            });
        }
        let key = digest(bearer?);
        if let Some(principal) = self.session(&key, Instant::now()) {
            return Some(principal);
        }
        self.tokens
            .get(&key)
            .map(|grant| grant.principal(Via::Token))
    }

    /// Checks a name and password, and starts a session if they match.
    pub async fn login(
        &self,
        name: &str,
        password: &str,
        address: Option<IpAddr>,
    ) -> Result<Login, LoginError> {
        if self.accounts.is_empty() {
            return Err(LoginError::NoAccounts);
        }
        let now = Instant::now();
        let network = address.map(limiter::network);
        let account = self.accounts.get(name);
        // Only real accounts are counted, so made-up names can't fill the
        // table or lock anyone out.
        let account_key = account.map(|_| name.to_owned());
        let wait = network
            .and_then(|n| self.by_address.retry_after(&n, now))
            .or_else(|| {
                let key = account_key.as_ref()?;
                self.by_account.retry_after(key, now)
            });
        // A name that isn't an account came from whoever is signing in, so
        // it's only logged quoted and cut short.
        let shown = match account {
            Some(_) => name.to_owned(),
            None => format!("unknown {:?}", name.chars().take(64).collect::<String>()),
        };
        if let Some(wait) = wait {
            self.audit
                .sign_in(&shown, "sign-in refused, too many attempts", address, false);
            return Err(LoginError::Limited(wait));
        }

        let hash = account.map_or(&self.decoy_hash, |a| &a.password_hash);
        let matches = password.len() <= MAX_PASSWORD_BYTES && self.verify(password, hash).await;
        let Some(account) = account.filter(|_| matches) else {
            if let Some(network) = network {
                self.by_address.fail(network, now);
            }
            if let Some(key) = account_key {
                self.by_account.fail(key, now);
            }
            self.audit.sign_in(&shown, "sign-in failed", address, false);
            return Err(LoginError::Invalid);
        };

        self.by_account.clear(&name.to_owned());
        let grant = Grant {
            name: name.into(),
            role: account.role,
        };
        let principal = grant.principal(Via::Session);
        let token = self.start_session(grant, Instant::now());
        self.audit.sign_in(name, "signed in", address, true);
        Ok(Login {
            token,
            principal,
            expires_in: self.session_max,
        })
    }

    /// Ends the session a bearer secret belongs to. API tokens can't be
    /// ended this way; remove them from the config instead.
    pub fn logout(&self, bearer: &str) {
        let removed = self.sessions.lock().unwrap().remove(&digest(bearer));
        if let Some(session) = removed {
            self.audit
                .record(&session.grant.name, "signed out", String::new());
        }
    }

    async fn verify(&self, password: &str, hash: &str) -> bool {
        let Ok(_permit) = self.checks.acquire().await else {
            return false;
        };
        let (password, hash) = (password.to_owned(), hash.to_owned());
        tokio::task::spawn_blocking(move || {
            Argon2::default()
                .verify_password(password.as_bytes(), hash.as_str())
                .is_ok()
        })
        .await
        .unwrap_or(false)
    }

    fn session(&self, key: &Digest, now: Instant) -> Option<Principal> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(key)?;
        if self.expired(session, now) {
            sessions.remove(key);
            return None;
        }
        session.last_used = now;
        Some(session.grant.principal(Via::Session))
    }

    fn expired(&self, session: &Session, now: Instant) -> bool {
        now.saturating_duration_since(session.last_used) >= self.session_idle
            || now.saturating_duration_since(session.started) >= self.session_max
    }

    fn start_session(&self, grant: Grant, now: Instant) -> String {
        let token = new_secret(SESSION_PREFIX);
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= MAX_SESSIONS {
            sessions.retain(|_, session| !self.expired(session, now));
        }
        if sessions.len() >= MAX_SESSIONS {
            let idlest = sessions.iter().min_by_key(|(_, s)| s.last_used);
            if let Some(key) = idlest.map(|(key, _)| *key) {
                sessions.remove(&key);
            }
        }
        let session = Session {
            grant,
            started: now,
            last_used: now,
        };
        sessions.insert(digest(&token), session);
        token
    }
}

/// An Argon2id hash of a password, in the PHC format `api.users` takes.
pub fn hash_password(password: &str) -> Result<String> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("hashing the password: {e}"))?;
    Ok(hash.to_string())
}

/// Checks that a `password_hash` from the config is an Argon2id hash.
pub fn check_password_hash(hash: &str) -> Result<()> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("not a password hash from `hushdns hash-password`: {e}"))?;
    anyhow::ensure!(
        parsed.algorithm == argon2::ARGON2ID_IDENT,
        "the hash is {}, not argon2id",
        parsed.algorithm
    );
    argon2::Params::try_from(&parsed).map_err(|e| anyhow::anyhow!("bad Argon2 parameters: {e}"))?;
    Ok(())
}

/// A new API token, and the hash of it that goes in `api.tokens`.
pub fn new_token() -> (String, String) {
    let token = new_secret(TOKEN_PREFIX);
    let hash = hex(&digest(&token));
    (token, hash)
}

/// Parses a token hash from `api.tokens`: 64 hex digits.
pub fn parse_token_hash(text: &str) -> Result<Digest> {
    anyhow::ensure!(
        text.len() == 64,
        "hash must be 64 hex digits, from `hushdns new-token`"
    );
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok();
        *byte = pair
            .and_then(|p| u8::from_str_radix(p, 16).ok())
            .context("hash must be 64 hex digits, from `hushdns new-token`")?;
    }
    Ok(out)
}

fn new_secret(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the system's random number generator failed");
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn digest(secret: &str) -> Digest {
    Sha256::digest(secret.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TokenConfig, UserConfig};

    fn config(users: &[(&str, &str, Role)], tokens: &[(&str, &str, Role)]) -> ApiConfig {
        ApiConfig {
            users: users
                .iter()
                .map(|(name, password, role)| UserConfig {
                    name: name.to_string(),
                    password_hash: hash_password(password).unwrap(),
                    role: *role,
                })
                .collect(),
            tokens: tokens
                .iter()
                .map(|(name, hash, role)| TokenConfig {
                    name: name.to_string(),
                    hash: hash.to_string(),
                    role: *role,
                })
                .collect(),
            ..ApiConfig::default()
        }
    }

    #[test]
    fn open_without_credentials() {
        let auth = Auth::new(&ApiConfig::default()).unwrap();
        assert!(!auth.required());
        let principal = auth.authenticate(None).unwrap();
        assert_eq!((principal.role, principal.via), (Role::Admin, Via::Open));
    }

    #[test]
    fn looks_up_tokens_by_hash() {
        let (token, hash) = new_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(hash.len(), 64);
        let mut config = config(&[], &[("script", &hash, Role::Viewer)]);
        config.token = Some("legacy-secret".into());
        let auth = Auth::new(&config).unwrap();

        let script = auth.authenticate(Some(&token)).unwrap();
        assert_eq!(&*script.name, "script");
        assert_eq!((script.role, script.via), (Role::Viewer, Via::Token));
        let legacy = auth.authenticate(Some("legacy-secret")).unwrap();
        assert_eq!(legacy.role, Role::Admin);
        assert!(auth.authenticate(Some("wrong")).is_none());
        assert!(auth.authenticate(None).is_none());
    }

    #[tokio::test]
    async fn signs_in_and_out() {
        let auth = Auth::new(&config(&[("ana", "correct horse", Role::Admin)], &[])).unwrap();
        let address = Some("192.0.2.1".parse().unwrap());
        assert!(matches!(
            auth.login("ana", "wrong", address).await,
            Err(LoginError::Invalid)
        ));
        assert!(matches!(
            auth.login("bob", "correct horse", address).await,
            Err(LoginError::Invalid)
        ));
        let Ok(login) = auth.login("ana", "correct horse", address).await else {
            panic!("sign-in failed");
        };
        assert!(login.token.starts_with(SESSION_PREFIX));
        let principal = auth.authenticate(Some(&login.token)).unwrap();
        assert_eq!(&*principal.name, "ana");
        assert_eq!((principal.role, principal.via), (Role::Admin, Via::Session));

        auth.logout(&login.token);
        assert!(auth.authenticate(Some(&login.token)).is_none());
        let actions: Vec<_> = auth.audit().recent().iter().map(|e| e.action).collect();
        assert_eq!(
            actions,
            [
                "signed out",
                "signed in",
                "sign-in failed",
                "sign-in failed"
            ]
        );
    }

    #[tokio::test]
    async fn limits_failed_sign_ins() {
        let auth = Auth::new(&config(&[("ana", "correct horse", Role::Viewer)], &[])).unwrap();
        let address = Some("192.0.2.1".parse().unwrap());
        for _ in 0..ACCOUNT_FAILURES {
            assert!(matches!(
                auth.login("ana", "guess", address).await,
                Err(LoginError::Invalid)
            ));
        }
        // Even the right password is refused until the window ends.
        assert!(matches!(
            auth.login("ana", "correct horse", Some("192.0.2.2".parse().unwrap()))
                .await,
            Err(LoginError::Limited(_))
        ));
    }

    #[tokio::test]
    async fn needs_accounts_to_sign_in() {
        let auth = Auth::new(&ApiConfig::default()).unwrap();
        assert!(matches!(
            auth.login("ana", "x", None).await,
            Err(LoginError::NoAccounts)
        ));
    }

    #[test]
    fn sessions_end_when_idle_or_old() {
        let mut config = config(&[], &[]);
        config.token = Some("x".into());
        config.session_idle_secs = 60;
        config.session_max_secs = 300;
        let auth = Auth::new(&config).unwrap();
        let grant = Grant {
            name: "ana".into(),
            role: Role::Viewer,
        };
        let start = Instant::now();
        let secs = Duration::from_secs;

        let idle = digest(&auth.start_session(grant.clone(), start));
        assert!(auth.session(&idle, start + secs(59)).is_some());
        assert!(auth.session(&idle, start + secs(118)).is_some());
        assert!(auth.session(&idle, start + secs(178)).is_none());

        let busy = digest(&auth.start_session(grant, start));
        for minute in 1..5 {
            assert!(auth.session(&busy, start + secs(minute * 59)).is_some());
        }
        assert!(auth.session(&busy, start + secs(300)).is_none());
    }

    #[test]
    fn checks_hashes_from_the_config() {
        check_password_hash(&hash_password("pw").unwrap()).unwrap();
        assert!(check_password_hash("plain text").is_err());
        let argon2i = "$argon2i$v=19$m=16,t=2,p=1$c29tZXNhbHQ$YWJjZGVmZ2hpamtsbW5vcA";
        assert!(check_password_hash(argon2i).is_err());

        let (_, hash) = new_token();
        assert!(parse_token_hash(&hash).is_ok());
        assert!(parse_token_hash(&hash.to_uppercase()).is_ok());
        assert!(parse_token_hash(&hash[1..]).is_err());
        assert!(parse_token_hash(&"z".repeat(64)).is_err());
        assert!(parse_token_hash(&"é".repeat(32)).is_err());
    }

    #[test]
    fn parses_roles() {
        assert_eq!("admin".parse::<Role>(), Ok(Role::Admin));
        assert!("root".parse::<Role>().is_err());
        assert!(Role::Admin > Role::Viewer);
    }
}

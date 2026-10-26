use crate::session_token;
use crate::session_types::Entry;
pub use crate::session_types::{BrowserSession, SessionError};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
/// Process-memory browser access only. Restart revokes all sessions. Not an identity authority.
pub struct SessionAuthority {
    pub(crate) sessions: BTreeMap<[u8; 32], Entry>,
    launch: Option<[u8; 32]>,
    ttl: Duration,
    max: usize,
    pub(crate) nonce_limit: usize,
}
impl SessionAuthority {
    pub fn new(
        ttl: Duration,
        max_sessions: usize,
        total_nonce_limit: usize,
    ) -> Result<Self, SessionError> {
        if !(Duration::from_secs(60)..=Duration::from_secs(86400)).contains(&ttl)
            || !(1..=256).contains(&max_sessions)
            || !(1..=65536).contains(&total_nonce_limit)
        {
            return Err(SessionError::Configuration);
        }
        Ok(Self {
            sessions: BTreeMap::new(),
            launch: None,
            ttl,
            max: max_sessions,
            nonce_limit: total_nonce_limit,
        })
    }
    /// Callers expose this once through their explicit local owner ceremony, never a log/query string.
    pub fn prepare_launch(&mut self) -> Result<String, SessionError> {
        if self.launch.is_some() {
            return Err(SessionError::Configuration);
        }
        let token = session_token::fresh()?;
        self.launch = Some(token);
        Ok(hex::encode(token))
    }
    pub fn launch(&mut self, token: &str) -> Result<BrowserSession, SessionError> {
        let expected = self.launch.ok_or(SessionError::LaunchConsumed)?;
        let actual = session_token::parse(token)?;
        if !bool::from(expected.ct_eq(&actual)) {
            return Err(SessionError::Rejected);
        }
        let session = self.issue()?;
        self.launch = None;
        Ok(session)
    }
    /// A caller must independently verify identity/grants before using this after external auth.
    pub fn issue(&mut self) -> Result<BrowserSession, SessionError> {
        self.prune();
        if self.sessions.len() >= self.max {
            return Err(SessionError::Capacity);
        }
        let id = session_token::fresh()?;
        let csrf = session_token::fresh()?;
        if self.sessions.contains_key(&id) {
            return Err(SessionError::RandomUnavailable);
        }
        let expires = Instant::now()
            .checked_add(self.ttl)
            .ok_or(SessionError::Clock)?;
        let expires_ms = session_token::now_ms()?
            .checked_add(u64::try_from(self.ttl.as_millis()).map_err(|_| SessionError::Clock)?)
            .filter(|v| *v <= 9_007_199_254_740_991)
            .ok_or(SessionError::Clock)?;
        self.sessions.insert(
            id,
            Entry {
                csrf,
                expires,
                expires_ms,
                nonces: BTreeSet::new(),
            },
        );
        Ok(BrowserSession {
            session_id: hex::encode(id),
            csrf_token: hex::encode(csrf),
            expires_at_unix_ms: expires_ms,
        })
    }
    pub fn authenticate(&mut self, id: &str) -> Result<BrowserSession, SessionError> {
        let id = session_token::parse(id)?;
        let entry = self.sessions.get(&id).ok_or(SessionError::Rejected)?;
        if entry.expires <= Instant::now() {
            self.sessions.remove(&id);
            return Err(SessionError::Expired);
        }
        Ok(BrowserSession {
            session_id: hex::encode(id),
            csrf_token: hex::encode(entry.csrf),
            expires_at_unix_ms: entry.expires_ms,
        })
    }
    pub fn revoke(&mut self, id: &str) -> Result<bool, SessionError> {
        Ok(self.sessions.remove(&session_token::parse(id)?).is_some())
    }
    pub(crate) fn prune(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, entry| entry.expires > now);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monotonic_expiry_releases_capacity_without_sleeping_or_public_fake_clock() {
        let mut authority = SessionAuthority::new(Duration::from_secs(60), 1, 2).unwrap();
        let first = authority.issue().unwrap();
        let id = session_token::parse(&first.session_id).unwrap();
        authority.sessions.get_mut(&id).unwrap().expires = Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            authority.authenticate(&first.session_id),
            Err(SessionError::Expired)
        ));
        assert!(authority.issue().is_ok());
    }
}

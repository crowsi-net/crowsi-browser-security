use std::{collections::BTreeSet, time::Instant};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Configuration,
    RandomUnavailable,
    Clock,
    Capacity,
    Rejected,
    Expired,
    LaunchConsumed,
    Csrf,
    Nonce,
    Replay,
    NonceCapacity,
}
/// Deliberately has no Debug: bearer/CSRF material must not enter default logs.
pub struct BrowserSession {
    pub session_id: String,
    pub csrf_token: String,
    pub expires_at_unix_ms: u64,
}
pub(crate) struct Entry {
    pub csrf: [u8; 32],
    pub expires: Instant,
    pub expires_ms: u64,
    pub nonces: BTreeSet<[u8; 16]>,
}

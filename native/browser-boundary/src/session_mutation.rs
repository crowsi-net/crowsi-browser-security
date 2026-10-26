use crate::{SessionAuthority, SessionError, session_token};
use subtle::ConstantTimeEq;
impl SessionAuthority {
    /// Enforces CSRF + one-use UUIDv4 within the existing session, never business authorization.
    pub fn authorize_mutation(
        &mut self,
        id: &str,
        csrf: &str,
        nonce: &str,
    ) -> Result<(), SessionError> {
        self.authenticate(id)?;
        let id = session_token::parse(id)?;
        let csrf = session_token::parse(csrf).map_err(|_| SessionError::Csrf)?;
        let entry = self.sessions.get(&id).ok_or(SessionError::Rejected)?;
        if !bool::from(entry.csrf.ct_eq(&csrf)) {
            return Err(SessionError::Csrf);
        }
        if nonce.len() != 36 {
            return Err(SessionError::Nonce);
        }
        let nonce = uuid::Uuid::parse_str(nonce).map_err(|_| SessionError::Nonce)?;
        if nonce.get_version_num() != 4 || nonce.get_variant() != uuid::Variant::RFC4122 {
            return Err(SessionError::Nonce);
        }
        if entry.nonces.contains(nonce.as_bytes()) {
            return Err(SessionError::Replay);
        }
        self.prune();
        if self
            .sessions
            .values()
            .map(|entry| entry.nonces.len())
            .sum::<usize>()
            >= self.nonce_limit
        {
            return Err(SessionError::NonceCapacity);
        }
        self.sessions
            .get_mut(&id)
            .ok_or(SessionError::Expired)?
            .nonces
            .insert(*nonce.as_bytes());
        Ok(())
    }
}

use crate::SessionError;
pub(crate) fn fresh() -> Result<[u8; 32], SessionError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| SessionError::RandomUnavailable)?;
    Ok(bytes)
}
pub(crate) fn parse(value: &str) -> Result<[u8; 32], SessionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SessionError::Rejected);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| SessionError::Rejected)?;
    Ok(bytes)
}
pub(crate) fn now_ms() -> Result<u64, SessionError> {
    let value = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SessionError::Clock)?
        .as_millis();
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or(SessionError::Clock)
}

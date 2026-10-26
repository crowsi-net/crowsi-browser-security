use crate::Failure;
use url::Url;

pub struct OwnerOrigin {
    origin: String,
    host: String,
    port: u16,
}
impl OwnerOrigin {
    pub fn parse(value: &str) -> Result<Self, Failure> {
        if value.len() > 256 {
            return Err(Failure::InvalidOwner);
        }
        let url = Url::parse(value).map_err(|_| Failure::InvalidOwner)?;
        let port = url.port().ok_or(Failure::InvalidOwner)?;
        if !matches!(url.scheme(), "http" | "https")
            || port < 1024
            || !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Failure::InvalidOwner);
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            host: format!("{}:{port}", url.host_str().ok_or(Failure::InvalidOwner)?),
            port,
        })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

//! Browser metadata and bounded opaque sessions; never human identity or product grants.
mod session;
mod session_mutation;
mod session_token;
mod session_types;
pub use session::{BrowserSession, SessionAuthority, SessionError};
mod origin;
mod request;
pub use origin::OwnerOrigin;
pub use request::{RequestBoundary, assess_request};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    InvalidOwner,
    Host,
    Origin,
    OriginRequired,
    FetchSite,
}
impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidOwner => "crowsi-browser-security-origin-invalid",
            Self::Host => "crowsi-browser-security-host-rejected",
            Self::Origin => "crowsi-browser-security-origin-rejected",
            Self::OriginRequired => "crowsi-browser-security-origin-required",
            Self::FetchSite => "crowsi-browser-security-fetch-site-rejected",
        }
    }
}

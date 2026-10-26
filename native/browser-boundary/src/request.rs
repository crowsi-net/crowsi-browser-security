use crate::{Failure, OwnerOrigin};

pub struct RequestBoundary<'a> {
    pub host: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub method: &'a str,
    pub fetch_site: Option<&'a str>,
}
pub fn assess_request(owner: &OwnerOrigin, request: RequestBoundary<'_>) -> Result<(), Failure> {
    if !request.host.is_some_and(|host| valid_host(owner, host)) {
        return Err(Failure::Host);
    }
    if request
        .origin
        .is_some_and(|origin| !origin.is_empty() && origin != owner.origin())
    {
        return Err(Failure::Origin);
    }
    if ["POST", "PUT", "PATCH", "DELETE"]
        .iter()
        .any(|method| request.method.eq_ignore_ascii_case(method))
        && request.origin != Some(owner.origin())
    {
        return Err(Failure::OriginRequired);
    }
    if request.fetch_site == Some("cross-site") {
        return Err(Failure::FetchSite);
    }
    Ok(())
}
fn valid_host(owner: &OwnerOrigin, host: &str) -> bool {
    if host.len() > 256 || host.trim() != host {
        return false;
    }
    let Some((name, port)) = host.rsplit_once(':') else {
        return false;
    };
    if !(name.eq_ignore_ascii_case("localhost") || matches!(name, "127.0.0.1" | "[::1]")) {
        return false;
    }
    port == owner.port().to_string()
}

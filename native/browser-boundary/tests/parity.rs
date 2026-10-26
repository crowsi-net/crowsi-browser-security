use crowsi_browser_boundary::{OwnerOrigin, RequestBoundary, assess_request};
#[test]
fn shared_javascript_and_native_vectors_retain_the_owner_contract() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../test-data/boundary-cases.json")).unwrap();
    assert_eq!(vectors["schemaVersion"], "crowsi-browser-boundary-cases/v1");
    for case in vectors["ownerCases"].as_array().unwrap() {
        let result = OwnerOrigin::parse(case["input"].as_str().unwrap());
        assert_eq!(
            result.as_ref().ok().map(|owner| owner.origin()),
            case["origin"].as_str(),
            "{case}"
        );
    }
    let owner = OwnerOrigin::parse("http://127.0.0.1:4317").unwrap();
    assert_eq!(owner.host(), "127.0.0.1:4317");
    for case in vectors["requestCases"].as_array().unwrap() {
        let result = assess_request(
            &owner,
            RequestBoundary {
                host: case["host"].as_str(),
                origin: case["origin"].as_str(),
                method: case["method"].as_str().unwrap(),
                fetch_site: case["fetchSite"].as_str(),
            },
        );
        assert_eq!(
            result.err().map(|error| error.code()),
            case["error"].as_str(),
            "{case}"
        );
    }
}

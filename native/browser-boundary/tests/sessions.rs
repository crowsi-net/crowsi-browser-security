use crowsi_browser_boundary::{SessionAuthority, SessionError};
use std::time::Duration;
fn authority(capacity: usize, nonces: usize) -> SessionAuthority {
    SessionAuthority::new(Duration::from_secs(60), capacity, nonces).unwrap()
}
#[test]
fn actual_os_random_launch_consumption_csrf_replay_revocation_and_restart() {
    let mut authority = authority(2, 4);
    let launch = authority.prepare_launch().unwrap();
    assert!(authority.prepare_launch().is_err());
    assert!(matches!(
        authority.launch(&"0".repeat(64)),
        Err(SessionError::Rejected)
    ));
    let session = authority.launch(&launch).unwrap();
    assert_eq!(session.session_id.len(), 64);
    assert_ne!(session.session_id, session.csrf_token);
    assert!(matches!(
        authority.launch(&launch),
        Err(SessionError::LaunchConsumed)
    ));
    assert_eq!(
        authority
            .authenticate(&session.session_id)
            .unwrap()
            .csrf_token,
        session.csrf_token
    );
    let nonce = "00000000-0000-4000-8000-000000000001";
    assert_eq!(
        authority.authorize_mutation(&session.session_id, &"0".repeat(64), nonce),
        Err(SessionError::Csrf)
    );
    authority
        .authorize_mutation(&session.session_id, &session.csrf_token, nonce)
        .unwrap();
    assert_eq!(
        authority.authorize_mutation(&session.session_id, &session.csrf_token, nonce),
        Err(SessionError::Replay)
    );
    assert!(authority.revoke(&session.session_id).unwrap());
    assert!(authority.authenticate(&session.session_id).is_err());
    assert!(super_authority().authenticate(&session.session_id).is_err());
}
fn super_authority() -> SessionAuthority {
    authority(1, 1)
}
#[test]
fn total_nonce_budget_is_shared_and_capacity_is_not_eviction() {
    let mut owner = authority(2, 1);
    let a = owner.issue().unwrap();
    let b = owner.issue().unwrap();
    assert!(matches!(owner.issue(), Err(SessionError::Capacity)));
    assert!(owner.authenticate(&a.session_id).is_ok());
    owner
        .authorize_mutation(
            &a.session_id,
            &a.csrf_token,
            "00000000-0000-4000-8000-000000000001",
        )
        .unwrap();
    assert_eq!(
        owner.authorize_mutation(
            &b.session_id,
            &b.csrf_token,
            "00000000-0000-4000-8000-000000000002"
        ),
        Err(SessionError::NonceCapacity)
    );
    owner.revoke(&a.session_id).unwrap();
    owner
        .authorize_mutation(
            &b.session_id,
            &b.csrf_token,
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap();
}
#[test]
fn rejects_invalid_configuration_tokens_and_nonce_without_granting_identity() {
    assert!(SessionAuthority::new(Duration::from_secs(1), 1, 1).is_err());
    assert!(SessionAuthority::new(Duration::from_secs(60), 257, 1).is_err());
    assert!(SessionAuthority::new(Duration::from_secs(60), 1, 65537).is_err());
    let mut owner = authority(1, 1);
    let a = owner.issue().unwrap();
    for bad in ["", "../../session", "A", &"x".repeat(4096)] {
        assert!(owner.authenticate(bad).is_err());
    }
    for bad in ["x", "00000000-0000-1000-8000-000000000001"] {
        assert_eq!(
            owner.authorize_mutation(&a.session_id, &a.csrf_token, bad),
            Err(SessionError::Nonce)
        );
    }
}

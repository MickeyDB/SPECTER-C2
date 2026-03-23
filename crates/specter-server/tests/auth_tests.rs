use specter_common::proto::specter::v1::OperatorRole;
use specter_server::auth::AuthService;
use specter_server::db;

async fn setup() -> AuthService {
    let pool = db::init_db(":memory:").await.unwrap();
    AuthService::new(pool)
}

#[tokio::test]
async fn create_operator_and_authenticate_flow_succeeds() {
    let svc = setup().await;

    let op = svc
        .create_operator("alice", "s3cure_P@ss!", "ADMIN")
        .await
        .unwrap();
    assert_eq!(op.username, "alice");
    assert_eq!(op.role, i32::from(OperatorRole::Admin));
    assert!(!op.id.is_empty());

    let (authed, token) = svc.authenticate("alice", "s3cure_P@ss!").await.unwrap();
    assert_eq!(authed.username, "alice");
    assert_eq!(token.len(), 64);

    // Token should be valid and carry correct context
    let ctx = svc.validate_token(&token).unwrap();
    assert_eq!(ctx.username, "alice");
    assert_eq!(ctx.role, "ADMIN");
    assert_eq!(ctx.operator_id, op.id);
}

#[tokio::test]
async fn invalid_credentials_are_rejected() {
    let svc = setup().await;
    svc.create_operator("bob", "goodpass", "OPERATOR")
        .await
        .unwrap();

    // Wrong password
    assert!(svc.authenticate("bob", "wrongpass").await.is_err());

    // Nonexistent user
    assert!(svc.authenticate("ghost", "pass").await.is_err());
}

#[tokio::test]
async fn rbac_permission_checks_for_all_roles() {
    // ADMIN can do everything
    assert!(AuthService::check_permission("ADMIN", "list_sessions"));
    assert!(AuthService::check_permission("ADMIN", "queue_task"));
    assert!(AuthService::check_permission("ADMIN", "create_listener"));
    assert!(AuthService::check_permission("ADMIN", "manage_operators"));
    assert!(AuthService::check_permission("ADMIN", "subscribe_events"));

    // OPERATOR can do everything except manage_operators
    assert!(AuthService::check_permission("OPERATOR", "list_sessions"));
    assert!(AuthService::check_permission("OPERATOR", "queue_task"));
    assert!(AuthService::check_permission("OPERATOR", "create_listener"));
    assert!(AuthService::check_permission("OPERATOR", "start_listener"));
    assert!(AuthService::check_permission(
        "OPERATOR",
        "subscribe_events"
    ));
    assert!(!AuthService::check_permission(
        "OPERATOR",
        "manage_operators"
    ));

    // OBSERVER is read-only
    assert!(AuthService::check_permission("OBSERVER", "list_sessions"));
    assert!(AuthService::check_permission("OBSERVER", "get_session"));
    assert!(AuthService::check_permission("OBSERVER", "list_operators"));
    assert!(AuthService::check_permission(
        "OBSERVER",
        "subscribe_events"
    ));
    assert!(!AuthService::check_permission("OBSERVER", "queue_task"));
    assert!(!AuthService::check_permission(
        "OBSERVER",
        "create_listener"
    ));
    assert!(!AuthService::check_permission(
        "OBSERVER",
        "manage_operators"
    ));

    // Unknown role denied
    assert!(!AuthService::check_permission("UNKNOWN", "list_sessions"));
    assert!(!AuthService::check_permission("", "list_sessions"));
}

#[tokio::test]
async fn default_admin_creation_on_empty_database() {
    let svc = setup().await;

    // First run — no operators
    assert!(svc.is_first_run().await.unwrap());
    assert!(svc.list_operators().await.unwrap().is_empty());

    // Create admin
    svc.create_operator("admin", "initial_pass", "ADMIN")
        .await
        .unwrap();

    // No longer first run
    assert!(!svc.is_first_run().await.unwrap());
    assert_eq!(svc.list_operators().await.unwrap().len(), 1);
}

#[tokio::test]
async fn duplicate_username_is_rejected() {
    let svc = setup().await;
    svc.create_operator("alice", "pass1", "ADMIN")
        .await
        .unwrap();

    let result = svc.create_operator("alice", "pass2", "OPERATOR").await;
    assert!(result.is_err(), "Duplicate username should be rejected");
}

#[tokio::test]
async fn validate_token_returns_none_for_invalid_token() {
    let svc = setup().await;
    assert!(svc.validate_token("bogus-token-value").is_none());
}

use specter_server::audit::{AuditAction, AuditFilter, AuditLog, ExportFormat};
use specter_server::db;

async fn test_pool() -> sqlx::SqlitePool {
    db::init_db(":memory:").await.unwrap()
}

#[tokio::test]
async fn append_creates_entries_with_valid_hash_chain() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "op1",
            AuditAction::ListenerCreate,
            "listener-1",
            &serde_json::json!({"port": 443}),
        )
        .await
        .unwrap();

    audit
        .append(
            "op1",
            AuditAction::TaskQueue,
            "session-abc",
            &serde_json::json!({"task": "whoami"}),
        )
        .await
        .unwrap();

    audit
        .append(
            "op2",
            AuditAction::TaskComplete,
            "session-abc",
            &serde_json::json!({"result": "admin"}),
        )
        .await
        .unwrap();

    let count = audit.verify_chain().await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn verify_chain_detects_entry_hash_tampering() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool.clone());

    audit
        .append(
            "op1",
            AuditAction::OperatorCreate,
            "user-a",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append(
            "op1",
            AuditAction::TaskQueue,
            "sess-1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();

    // Tamper with the entry hash of the first record
    sqlx::query("UPDATE audit_log SET entry_hash = 'deadbeef' WHERE sequence_number = 1")
        .execute(&pool)
        .await
        .unwrap();

    let result = audit.verify_chain().await;
    assert!(result.is_err(), "should detect tampered entry_hash");
}

#[tokio::test]
async fn verify_chain_detects_prev_hash_tampering() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool.clone());

    audit
        .append(
            "op1",
            AuditAction::OperatorCreate,
            "u1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append("op1", AuditAction::CertIssue, "u1", &serde_json::json!({}))
        .await
        .unwrap();

    // Tamper with prev_hash of the second entry
    sqlx::query("UPDATE audit_log SET prev_hash = 'corrupted' WHERE sequence_number = 2")
        .execute(&pool)
        .await
        .unwrap();

    let result = audit.verify_chain().await;
    assert!(result.is_err(), "should detect tampered prev_hash");
}

#[tokio::test]
async fn verify_chain_detects_content_modification() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool.clone());

    audit
        .append(
            "op1",
            AuditAction::TaskQueue,
            "s1",
            &serde_json::json!({"cmd": "ls"}),
        )
        .await
        .unwrap();

    // Modify the action field — hash won't match
    sqlx::query("UPDATE audit_log SET action = 'LISTENER_CREATE' WHERE sequence_number = 1")
        .execute(&pool)
        .await
        .unwrap();

    let result = audit.verify_chain().await;
    assert!(result.is_err(), "should detect content modification");
}

#[tokio::test]
async fn empty_audit_log_verifies_successfully() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    let count = audit.verify_chain().await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn first_entry_has_empty_prev_hash() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "op1",
            AuditAction::OperatorCreate,
            "admin",
            &serde_json::json!({}),
        )
        .await
        .unwrap();

    let entries = audit.query(&AuditFilter::default()).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].prev_hash, "");
    assert!(!entries[0].entry_hash.is_empty());
}

#[tokio::test]
async fn sequence_numbers_are_monotonic_and_gap_free() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    for i in 0..10 {
        audit
            .append(
                "op1",
                AuditAction::TaskQueue,
                &format!("target-{i}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
    }

    let entries = audit.query(&AuditFilter::default()).await.unwrap();
    assert_eq!(entries.len(), 10);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence_number, (i + 1) as i64);
    }
}

#[tokio::test]
async fn query_filters_by_operator() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "alice",
            AuditAction::TaskQueue,
            "s1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append("bob", AuditAction::TaskQueue, "s2", &serde_json::json!({}))
        .await
        .unwrap();
    audit
        .append(
            "alice",
            AuditAction::TaskComplete,
            "s1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();

    let filter = AuditFilter {
        operator_id: Some("alice".to_string()),
        ..Default::default()
    };
    let entries = audit.query(&filter).await.unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.operator_id == "alice"));
}

#[tokio::test]
async fn query_filters_by_action() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append("op1", AuditAction::TaskQueue, "s1", &serde_json::json!({}))
        .await
        .unwrap();
    audit
        .append(
            "op1",
            AuditAction::ListenerCreate,
            "l1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append("op1", AuditAction::TaskQueue, "s2", &serde_json::json!({}))
        .await
        .unwrap();

    let filter = AuditFilter {
        action: Some("LISTENER_CREATE".to_string()),
        ..Default::default()
    };
    let entries = audit.query(&filter).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "LISTENER_CREATE");
}

#[tokio::test]
async fn query_filters_by_target() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "op1",
            AuditAction::TaskQueue,
            "session-abc",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append(
            "op1",
            AuditAction::TaskQueue,
            "session-xyz",
            &serde_json::json!({}),
        )
        .await
        .unwrap();

    let filter = AuditFilter {
        target: Some("session-abc".to_string()),
        ..Default::default()
    };
    let entries = audit.query(&filter).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].target, "session-abc");
}

#[tokio::test]
async fn query_with_combined_filters() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "alice",
            AuditAction::TaskQueue,
            "s1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append(
            "alice",
            AuditAction::ListenerCreate,
            "l1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append("bob", AuditAction::TaskQueue, "s1", &serde_json::json!({}))
        .await
        .unwrap();

    let filter = AuditFilter {
        operator_id: Some("alice".to_string()),
        action: Some("TASK_QUEUE".to_string()),
        ..Default::default()
    };
    let entries = audit.query(&filter).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].operator_id, "alice");
    assert_eq!(entries[0].action, "TASK_QUEUE");
}

#[tokio::test]
async fn export_json_produces_valid_json() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "op1",
            AuditAction::TaskQueue,
            "s1",
            &serde_json::json!({"cmd": "whoami"}),
        )
        .await
        .unwrap();
    audit
        .append(
            "op2",
            AuditAction::CertIssue,
            "user-bob",
            &serde_json::json!({"days": 90}),
        )
        .await
        .unwrap();

    let json = audit
        .export(&AuditFilter::default(), ExportFormat::Json)
        .await
        .unwrap();

    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0]["operator_id"], "op1");
    assert_eq!(parsed[0]["action"], "TASK_QUEUE");
    assert_eq!(parsed[1]["operator_id"], "op2");
    assert_eq!(parsed[1]["action"], "CERT_ISSUE");
}

#[tokio::test]
async fn export_csv_has_header_and_correct_row_count() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    for i in 0..5 {
        audit
            .append(
                &format!("op{i}"),
                AuditAction::TaskQueue,
                &format!("s{i}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
    }

    let csv = audit
        .export(&AuditFilter::default(), ExportFormat::Csv)
        .await
        .unwrap();

    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 6); // header + 5 entries
    assert!(lines[0].starts_with("id,sequence_number,"));
}

#[tokio::test]
async fn export_with_filter_only_includes_matching() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    audit
        .append(
            "alice",
            AuditAction::TaskQueue,
            "s1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    audit
        .append(
            "bob",
            AuditAction::ListenerCreate,
            "l1",
            &serde_json::json!({}),
        )
        .await
        .unwrap();

    let filter = AuditFilter {
        operator_id: Some("bob".to_string()),
        ..Default::default()
    };
    let json = audit.export(&filter, ExportFormat::Json).await.unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["operator_id"], "bob");
}

#[tokio::test]
async fn each_entry_has_unique_id() {
    let pool = test_pool().await;
    let audit = AuditLog::new(pool);

    let id1 = audit
        .append("op1", AuditAction::TaskQueue, "s1", &serde_json::json!({}))
        .await
        .unwrap();
    let id2 = audit
        .append("op1", AuditAction::TaskQueue, "s2", &serde_json::json!({}))
        .await
        .unwrap();
    let id3 = audit
        .append("op1", AuditAction::TaskQueue, "s3", &serde_json::json!({}))
        .await
        .unwrap();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

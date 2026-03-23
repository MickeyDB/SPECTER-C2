use sqlx::SqlitePool;

pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            username TEXT NOT NULL,
            pid INTEGER NOT NULL,
            os_version TEXT NOT NULL DEFAULT '',
            integrity_level TEXT NOT NULL DEFAULT '',
            process_name TEXT NOT NULL DEFAULT '',
            internal_ip TEXT NOT NULL DEFAULT '',
            external_ip TEXT NOT NULL DEFAULT '',
            last_checkin INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            active_channel TEXT NOT NULL DEFAULT 'http',
            implant_pubkey BLOB,
            deleted INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            task_type TEXT NOT NULL,
            arguments BLOB,
            priority TEXT NOT NULL DEFAULT 'NORMAL',
            status TEXT NOT NULL DEFAULT 'QUEUED',
            created_at INTEGER NOT NULL,
            completed_at INTEGER,
            operator_id TEXT NOT NULL DEFAULT '',
            result BLOB,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS operators (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'OPERATOR',
            created_at INTEGER NOT NULL,
            last_login INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS listeners (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            bind_address TEXT NOT NULL DEFAULT '0.0.0.0',
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'http',
            status TEXT NOT NULL DEFAULT 'STOPPED',
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            sequence_number INTEGER NOT NULL UNIQUE,
            operator_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            timestamp INTEGER NOT NULL,
            prev_hash TEXT NOT NULL DEFAULT '',
            entry_hash TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS module_repository (
            module_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '1.0.0',
            module_type TEXT NOT NULL DEFAULT 'PIC',
            description TEXT NOT NULL DEFAULT '',
            blob BLOB NOT NULL,
            signature BLOB,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(name, version)
        )",
    )
    .execute(pool)
    .await?;

    // CA key material — stores root CA cert + encrypted private key
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ca_state (
            id TEXT PRIMARY KEY DEFAULT 'root',
            ca_cert_pem TEXT NOT NULL,
            ca_key_pem_encrypted BLOB NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Issued certificates tracking
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS certificates (
            serial TEXT PRIMARY KEY,
            subject_cn TEXT NOT NULL,
            subject_ou TEXT NOT NULL DEFAULT '',
            cert_pem TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            revoked_at INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            yaml_content TEXT NOT NULL,
            compiled_blob BLOB,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT NOT NULL DEFAULT '',
            event_filters TEXT NOT NULL DEFAULT '[]',
            format TEXT NOT NULL DEFAULT 'GenericJSON',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            listener_id TEXT NOT NULL DEFAULT ''
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS campaign_sessions (
            campaign_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            added_at INTEGER NOT NULL,
            PRIMARY KEY (campaign_id, session_id),
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS campaign_operators (
            campaign_id TEXT NOT NULL,
            operator_id TEXT NOT NULL,
            access_level TEXT NOT NULL DEFAULT 'FULL',
            added_at INTEGER NOT NULL,
            PRIMARY KEY (campaign_id, operator_id),
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
            FOREIGN KEY (operator_id) REFERENCES operators(id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS redirectors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            redirector_type TEXT NOT NULL,
            provider TEXT NOT NULL,
            domain TEXT NOT NULL,
            alternative_domains TEXT NOT NULL DEFAULT '[]',
            tls_cert_mode TEXT NOT NULL DEFAULT 'Acme',
            backend_url TEXT NOT NULL,
            filtering_rules TEXT NOT NULL DEFAULT '{}',
            health_check_interval INTEGER NOT NULL DEFAULT 60,
            auto_rotate_on_block INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'Provisioning',
            config_yaml TEXT NOT NULL,
            terraform_state BLOB,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS domain_pool (
            domain TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'available',
            redirector_id TEXT,
            added_at INTEGER NOT NULL,
            burned_at INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cert_records (
            domain TEXT PRIMARY KEY,
            redirector_id TEXT NOT NULL,
            not_after INTEGER NOT NULL,
            challenge_type TEXT NOT NULL DEFAULT 'http-01',
            FOREIGN KEY (redirector_id) REFERENCES redirectors(id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS azure_listeners (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            config_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'STOPPED',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS azure_containers (
            session_id TEXT PRIMARY KEY,
            listener_id TEXT NOT NULL,
            container_name TEXT NOT NULL UNIQUE,
            sas_token TEXT NOT NULL,
            encryption_key_hex TEXT NOT NULL,
            next_cmd_seq INTEGER NOT NULL DEFAULT 0,
            next_result_seq INTEGER NOT NULL DEFAULT 0,
            provisioned INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (listener_id) REFERENCES azure_listeners(id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            campaign_name TEXT NOT NULL,
            format TEXT NOT NULL DEFAULT 'markdown',
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS chat_messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            sender_username TEXT NOT NULL,
            content TEXT NOT NULL,
            channel TEXT NOT NULL DEFAULT 'global',
            timestamp INTEGER NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES operators(id)
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

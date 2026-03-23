use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("report not found: {0}")]
    NotFound(String),

    #[error("campaign not found: {0}")]
    CampaignNotFound(String),
}

/// Which sections to include in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludeSections {
    pub timeline: bool,
    pub ioc_list: bool,
    pub findings: bool,
    pub recommendations: bool,
}

impl Default for IncludeSections {
    fn default() -> Self {
        Self {
            timeline: true,
            ioc_list: true,
            findings: true,
            recommendations: true,
        }
    }
}

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Markdown,
    Json,
}

impl ReportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Json => "json",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Markdown,
        }
    }

    pub fn from_proto(v: i32) -> Self {
        match v {
            1 => Self::Json,
            _ => Self::Markdown,
        }
    }

    pub fn to_proto(self) -> i32 {
        match self {
            Self::Markdown => 0,
            Self::Json => 1,
        }
    }
}

/// Configuration for generating a report.
#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub campaign_id: String,
    pub time_range_start: Option<i64>,
    pub time_range_end: Option<i64>,
    pub include_sections: IncludeSections,
    pub operator_filter: Option<String>,
    pub format: ReportFormat,
}

/// A generated report stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub campaign_id: String,
    pub campaign_name: String,
    pub format: String,
    pub content: String,
    pub created_at: i64,
    pub created_by: String,
}

/// IOC types extracted from task results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: String,
    pub value: String,
    pub context: String,
}

/// A timeline entry for the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: i64,
    pub operator: String,
    pub session_hostname: String,
    pub task_type: String,
    pub status: String,
    pub result_summary: String,
}

/// Executive summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub campaign_name: String,
    pub campaign_description: String,
    pub total_sessions: i64,
    pub total_tasks: i64,
    pub successful_tasks: i64,
    pub failed_tasks: i64,
    pub unique_operators: i64,
    pub time_range_start: String,
    pub time_range_end: String,
}

/// Complete report data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub summary: ExecutiveSummary,
    pub timeline: Vec<TimelineEntry>,
    pub iocs: Vec<Ioc>,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

pub struct ReportGenerator {
    pool: SqlitePool,
}

impl ReportGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Generate a report based on the given configuration.
    pub async fn generate_report(
        &self,
        config: &ReportConfig,
        operator_id: &str,
    ) -> Result<Report, ReportError> {
        // Verify campaign exists
        let campaign = sqlx::query("SELECT id, name, description FROM campaigns WHERE id = ?1")
            .bind(&config.campaign_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| ReportError::CampaignNotFound(config.campaign_id.clone()))?;

        let campaign_name: String = campaign.get("name");
        let campaign_description: String = campaign.get("description");

        // Get sessions for this campaign
        let session_ids: Vec<String> =
            sqlx::query_scalar("SELECT session_id FROM campaign_sessions WHERE campaign_id = ?1")
                .bind(&config.campaign_id)
                .fetch_all(&self.pool)
                .await?;

        // Build report data
        let summary = self
            .build_summary(
                &config.campaign_id,
                &campaign_name,
                &campaign_description,
                &session_ids,
                config,
            )
            .await?;

        let timeline = if config.include_sections.timeline {
            self.build_timeline(&session_ids, config).await?
        } else {
            vec![]
        };

        let iocs = if config.include_sections.ioc_list {
            self.extract_iocs(&session_ids, config).await?
        } else {
            vec![]
        };

        let findings = if config.include_sections.findings {
            self.extract_findings(&session_ids, config).await?
        } else {
            vec![]
        };

        let report_data = ReportData {
            summary,
            timeline,
            iocs,
            findings,
            recommendations: if config.include_sections.recommendations {
                vec!["[Add manual recommendations here]".to_string()]
            } else {
                vec![]
            },
        };

        // Render
        let content = match config.format {
            ReportFormat::Markdown => render_markdown(&report_data),
            ReportFormat::Json => render_json(&report_data),
        };

        // Store
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO reports (id, campaign_id, campaign_name, format, content, created_at, created_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&id)
        .bind(&config.campaign_id)
        .bind(&campaign_name)
        .bind(config.format.as_str())
        .bind(&content)
        .bind(now)
        .bind(operator_id)
        .execute(&self.pool)
        .await?;

        Ok(Report {
            id,
            campaign_id: config.campaign_id.clone(),
            campaign_name,
            format: config.format.as_str().to_string(),
            content,
            created_at: now,
            created_by: operator_id.to_string(),
        })
    }

    /// List all generated reports.
    pub async fn list_reports(&self) -> Result<Vec<Report>, ReportError> {
        let rows = sqlx::query(
            "SELECT id, campaign_id, campaign_name, format, created_at, created_by FROM reports ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Report {
                id: r.get("id"),
                campaign_id: r.get("campaign_id"),
                campaign_name: r.get("campaign_name"),
                format: r.get("format"),
                content: String::new(), // Don't load content in list
                created_at: r.get("created_at"),
                created_by: r.get("created_by"),
            })
            .collect())
    }

    /// Get a single report by ID.
    pub async fn get_report(&self, report_id: &str) -> Result<Report, ReportError> {
        let row = sqlx::query(
            "SELECT id, campaign_id, campaign_name, format, content, created_at, created_by FROM reports WHERE id = ?1",
        )
        .bind(report_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ReportError::NotFound(report_id.to_string()))?;

        Ok(Report {
            id: row.get("id"),
            campaign_id: row.get("campaign_id"),
            campaign_name: row.get("campaign_name"),
            format: row.get("format"),
            content: row.get("content"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
        })
    }

    async fn build_summary(
        &self,
        _campaign_id: &str,
        campaign_name: &str,
        campaign_description: &str,
        session_ids: &[String],
        config: &ReportConfig,
    ) -> Result<ExecutiveSummary, ReportError> {
        let total_sessions = session_ids.len() as i64;

        let placeholders = make_placeholders(session_ids.len());

        // Query task counts with optional time/operator filter
        let (total_tasks, successful_tasks, failed_tasks, unique_operators) = if session_ids
            .is_empty()
        {
            (0i64, 0i64, 0i64, 0i64)
        } else {
            let base_query = format!(
                "SELECT \
                    COUNT(*) as total, \
                    SUM(CASE WHEN status = 'COMPLETE' THEN 1 ELSE 0 END) as success, \
                    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed, \
                    COUNT(DISTINCT operator_id) as operators \
                 FROM tasks WHERE session_id IN ({placeholders}){}{}",
                time_filter_sql(config),
                operator_filter_sql(config),
            );

            let mut query = sqlx::query(&base_query);
            for sid in session_ids {
                query = query.bind(sid);
            }
            if let Some(start) = config.time_range_start {
                query = query.bind(start);
            }
            if let Some(end) = config.time_range_end {
                query = query.bind(end);
            }
            if let Some(ref op) = config.operator_filter {
                query = query.bind(op);
            }

            let row = query.fetch_one(&self.pool).await?;
            (
                row.get::<i64, _>("total"),
                row.get::<i64, _>("success"),
                row.get::<i64, _>("failed"),
                row.get::<i64, _>("operators"),
            )
        };

        let time_start = config
            .time_range_start
            .map(|ts| format_timestamp(ts))
            .unwrap_or_else(|| "beginning".to_string());
        let time_end = config
            .time_range_end
            .map(|ts| format_timestamp(ts))
            .unwrap_or_else(|| "now".to_string());

        Ok(ExecutiveSummary {
            campaign_name: campaign_name.to_string(),
            campaign_description: campaign_description.to_string(),
            total_sessions,
            total_tasks,
            successful_tasks,
            failed_tasks,
            unique_operators,
            time_range_start: time_start,
            time_range_end: time_end,
        })
    }

    async fn build_timeline(
        &self,
        session_ids: &[String],
        config: &ReportConfig,
    ) -> Result<Vec<TimelineEntry>, ReportError> {
        if session_ids.is_empty() {
            return Ok(vec![]);
        }

        let placeholders = make_placeholders(session_ids.len());
        let query_str = format!(
            "SELECT t.created_at, t.operator_id, t.task_type, t.status, t.result, \
                    s.hostname \
             FROM tasks t JOIN sessions s ON t.session_id = s.id \
             WHERE t.session_id IN ({placeholders}){}{} \
             ORDER BY t.created_at ASC",
            time_filter_sql(config),
            operator_filter_sql(config),
        );

        let mut query = sqlx::query(&query_str);
        for sid in session_ids {
            query = query.bind(sid);
        }
        if let Some(start) = config.time_range_start {
            query = query.bind(start);
        }
        if let Some(end) = config.time_range_end {
            query = query.bind(end);
        }
        if let Some(ref op) = config.operator_filter {
            query = query.bind(op);
        }

        let rows = query.fetch_all(&self.pool).await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let result_bytes: Option<Vec<u8>> = r.get("result");
                let result_summary = result_bytes
                    .map(|b| {
                        let s = String::from_utf8_lossy(&b);
                        if s.len() > 200 {
                            format!("{}...", &s[..200])
                        } else {
                            s.to_string()
                        }
                    })
                    .unwrap_or_default();

                TimelineEntry {
                    timestamp: r.get("created_at"),
                    operator: r.get("operator_id"),
                    session_hostname: r.get("hostname"),
                    task_type: r.get("task_type"),
                    status: r.get("status"),
                    result_summary,
                }
            })
            .collect())
    }

    async fn extract_iocs(
        &self,
        session_ids: &[String],
        config: &ReportConfig,
    ) -> Result<Vec<Ioc>, ReportError> {
        if session_ids.is_empty() {
            return Ok(vec![]);
        }

        let placeholders = make_placeholders(session_ids.len());
        let query_str = format!(
            "SELECT t.result, t.task_type, s.hostname \
             FROM tasks t JOIN sessions s ON t.session_id = s.id \
             WHERE t.session_id IN ({placeholders}) AND t.result IS NOT NULL{}{}",
            time_filter_sql(config),
            operator_filter_sql(config),
        );

        let mut query = sqlx::query(&query_str);
        for sid in session_ids {
            query = query.bind(sid);
        }
        if let Some(start) = config.time_range_start {
            query = query.bind(start);
        }
        if let Some(end) = config.time_range_end {
            query = query.bind(end);
        }
        if let Some(ref op) = config.operator_filter {
            query = query.bind(op);
        }

        let rows = query.fetch_all(&self.pool).await?;

        let mut iocs = Vec::new();
        for row in rows {
            let result_bytes: Vec<u8> = row.get("result");
            let task_type: String = row.get("task_type");
            let hostname: String = row.get("hostname");
            let text = String::from_utf8_lossy(&result_bytes);
            let context = format!("{} on {}", task_type, hostname);

            extract_iocs_from_text(&text, &context, &mut iocs);
        }

        // Deduplicate
        iocs.sort_by(|a, b| (&a.ioc_type, &a.value).cmp(&(&b.ioc_type, &b.value)));
        iocs.dedup_by(|a, b| a.ioc_type == b.ioc_type && a.value == b.value);

        Ok(iocs)
    }

    async fn extract_findings(
        &self,
        session_ids: &[String],
        config: &ReportConfig,
    ) -> Result<Vec<String>, ReportError> {
        if session_ids.is_empty() {
            return Ok(vec![]);
        }

        // Build findings from completed tasks that indicate interesting activity
        let placeholders = make_placeholders(session_ids.len());
        let query_str = format!(
            "SELECT t.task_type, t.status, s.hostname, s.username, s.integrity_level \
             FROM tasks t JOIN sessions s ON t.session_id = s.id \
             WHERE t.session_id IN ({placeholders}) AND t.status = 'COMPLETE'{}{}",
            time_filter_sql(config),
            operator_filter_sql(config),
        );

        let mut query = sqlx::query(&query_str);
        for sid in session_ids {
            query = query.bind(sid);
        }
        if let Some(start) = config.time_range_start {
            query = query.bind(start);
        }
        if let Some(end) = config.time_range_end {
            query = query.bind(end);
        }
        if let Some(ref op) = config.operator_filter {
            query = query.bind(op);
        }

        let rows = query.fetch_all(&self.pool).await?;

        let mut findings = Vec::new();
        for row in &rows {
            let task_type: String = row.get("task_type");
            let hostname: String = row.get("hostname");
            let username: String = row.get("username");
            let integrity: String = row.get("integrity_level");

            match task_type.as_str() {
                "lateral" | "psexec" | "wmi" | "dcom" | "winrm" => {
                    findings.push(format!(
                        "Lateral movement via {} succeeded on {} as {}",
                        task_type, hostname, username
                    ));
                }
                "inject" | "shellcode" => {
                    findings.push(format!(
                        "Process injection ({}) executed on {} (integrity: {})",
                        task_type, hostname, integrity
                    ));
                }
                "token" => {
                    findings.push(format!(
                        "Token manipulation performed on {} as {}",
                        hostname, username
                    ));
                }
                _ => {}
            }
        }

        findings.sort();
        findings.dedup();
        Ok(findings)
    }
}

// ── IOC Extraction ──────────────────────────────────────────────────

fn extract_iocs_from_text(text: &str, context: &str, iocs: &mut Vec<Ioc>) {
    // IPv4 addresses
    for cap in regex_lite::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        .unwrap()
        .find_iter(text)
    {
        let ip = cap.as_str();
        // Skip common non-IOC IPs
        if !ip.starts_with("0.") && !ip.starts_with("127.") && ip != "255.255.255.255" {
            iocs.push(Ioc {
                ioc_type: "ip".to_string(),
                value: ip.to_string(),
                context: context.to_string(),
            });
        }
    }

    // Domain names (simple heuristic)
    for cap in regex_lite::Regex::new(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b")
        .unwrap()
        .find_iter(text)
    {
        let domain = cap.as_str().to_lowercase();
        // Skip common non-IOC domains
        if !domain.ends_with(".local")
            && !domain.ends_with(".internal")
            && !domain.ends_with(".localdomain")
            && domain.contains('.')
        {
            iocs.push(Ioc {
                ioc_type: "domain".to_string(),
                value: domain,
                context: context.to_string(),
            });
        }
    }

    // SHA256 hashes
    for cap in regex_lite::Regex::new(r"\b[a-fA-F0-9]{64}\b")
        .unwrap()
        .find_iter(text)
    {
        iocs.push(Ioc {
            ioc_type: "sha256".to_string(),
            value: cap.as_str().to_lowercase(),
            context: context.to_string(),
        });
    }

    // MD5 hashes
    for cap in regex_lite::Regex::new(r"\b[a-fA-F0-9]{32}\b")
        .unwrap()
        .find_iter(text)
    {
        iocs.push(Ioc {
            ioc_type: "md5".to_string(),
            value: cap.as_str().to_lowercase(),
            context: context.to_string(),
        });
    }

    // Named pipes
    for cap in regex_lite::Regex::new(r"\\\\\.\\pipe\\([^\s\\]+)")
        .unwrap()
        .find_iter(text)
    {
        iocs.push(Ioc {
            ioc_type: "named_pipe".to_string(),
            value: cap.as_str().to_string(),
            context: context.to_string(),
        });
    }

    // Service names (from sc query / service output)
    for cap in regex_lite::Regex::new(r"SERVICE_NAME:\s*(\S+)")
        .unwrap()
        .captures_iter(text)
    {
        if let Some(m) = cap.get(1) {
            iocs.push(Ioc {
                ioc_type: "service".to_string(),
                value: m.as_str().to_string(),
                context: context.to_string(),
            });
        }
    }

    // Process names (common executables)
    for cap in regex_lite::Regex::new(r"\b(\w+\.exe)\b")
        .unwrap()
        .find_iter(text)
    {
        let proc = cap.as_str().to_lowercase();
        iocs.push(Ioc {
            ioc_type: "process".to_string(),
            value: proc,
            context: context.to_string(),
        });
    }
}

// ── Rendering ───────────────────────────────────────────────────────

fn render_markdown(data: &ReportData) -> String {
    let mut md = String::new();

    md.push_str("# SPECTER Engagement Report\n\n");

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&format!("**Campaign:** {}\n\n", data.summary.campaign_name));
    if !data.summary.campaign_description.is_empty() {
        md.push_str(&format!(
            "**Description:** {}\n\n",
            data.summary.campaign_description
        ));
    }
    md.push_str(&format!(
        "**Period:** {} — {}\n\n",
        data.summary.time_range_start, data.summary.time_range_end
    ));
    md.push_str(&format!(
        "| Metric | Value |\n|--------|-------|\n\
         | Total Sessions | {} |\n\
         | Total Tasks | {} |\n\
         | Successful Tasks | {} |\n\
         | Failed Tasks | {} |\n\
         | Unique Operators | {} |\n\n",
        data.summary.total_sessions,
        data.summary.total_tasks,
        data.summary.successful_tasks,
        data.summary.failed_tasks,
        data.summary.unique_operators,
    ));

    // Timeline
    if !data.timeline.is_empty() {
        md.push_str("## Timeline of Actions\n\n");
        md.push_str("| Time | Operator | Target | Task | Status | Result |\n");
        md.push_str("|------|----------|--------|------|--------|--------|\n");
        for entry in &data.timeline {
            let ts = format_timestamp(entry.timestamp);
            let result = entry
                .result_summary
                .replace('|', "\\|")
                .replace('\n', " ");
            let result_short = if result.len() > 80 {
                format!("{}...", &result[..80])
            } else {
                result
            };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                ts,
                entry.operator,
                entry.session_hostname,
                entry.task_type,
                entry.status,
                result_short,
            ));
        }
        md.push_str("\n");
    }

    // IOCs
    if !data.iocs.is_empty() {
        md.push_str("## Indicators of Compromise (IOCs)\n\n");
        md.push_str("| Type | Value | Context |\n");
        md.push_str("|------|-------|---------|\n");
        for ioc in &data.iocs {
            md.push_str(&format!(
                "| {} | `{}` | {} |\n",
                ioc.ioc_type, ioc.value, ioc.context
            ));
        }
        md.push_str("\n");
    }

    // Findings
    if !data.findings.is_empty() {
        md.push_str("## Findings\n\n");
        for finding in &data.findings {
            md.push_str(&format!("- {finding}\n"));
        }
        md.push_str("\n");
    }

    // Recommendations
    if !data.recommendations.is_empty() {
        md.push_str("## Recommendations\n\n");
        for rec in &data.recommendations {
            md.push_str(&format!("- {rec}\n"));
        }
        md.push_str("\n");
    }

    md.push_str("---\n\n*Generated by SPECTER C2 Framework*\n");

    md
}

fn render_json(data: &ReportData) -> String {
    serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn make_placeholders(count: usize) -> String {
    (1..=count)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn time_filter_sql(config: &ReportConfig) -> String {
    let mut s = String::new();
    if config.time_range_start.is_some() {
        s.push_str(" AND t.created_at >= ?");
    }
    if config.time_range_end.is_some() {
        s.push_str(" AND t.created_at <= ?");
    }
    s
}

fn operator_filter_sql(config: &ReportConfig) -> String {
    if config.operator_filter.is_some() {
        " AND t.operator_id = ?".to_string()
    } else {
        String::new()
    }
}

fn format_timestamp(ts: i64) -> String {
    // Timestamps could be seconds or milliseconds; handle both
    let dt = if ts > 1_000_000_000_000 {
        // milliseconds
        Utc.timestamp_millis_opt(ts)
            .single()
            .unwrap_or_else(|| Utc::now())
    } else {
        // seconds
        Utc.timestamp_opt(ts, 0)
            .single()
            .unwrap_or_else(|| Utc::now())
    };
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_extraction_ipv4() {
        let mut iocs = Vec::new();
        extract_iocs_from_text("Connected to 192.168.1.100 on port 443", "test", &mut iocs);
        assert!(iocs.iter().any(|i| i.ioc_type == "ip" && i.value == "192.168.1.100"));
    }

    #[test]
    fn test_ioc_extraction_skips_loopback() {
        let mut iocs = Vec::new();
        extract_iocs_from_text("localhost 127.0.0.1", "test", &mut iocs);
        assert!(!iocs.iter().any(|i| i.ioc_type == "ip" && i.value == "127.0.0.1"));
    }

    #[test]
    fn test_ioc_extraction_sha256() {
        let mut iocs = Vec::new();
        let hash = "a" .repeat(64);
        extract_iocs_from_text(&format!("hash: {hash}"), "test", &mut iocs);
        assert!(iocs.iter().any(|i| i.ioc_type == "sha256"));
    }

    #[test]
    fn test_ioc_extraction_named_pipe() {
        let mut iocs = Vec::new();
        extract_iocs_from_text(r"\\.\pipe\evil_pipe connected", "test", &mut iocs);
        assert!(iocs.iter().any(|i| i.ioc_type == "named_pipe"));
    }

    #[test]
    fn test_ioc_extraction_process() {
        let mut iocs = Vec::new();
        extract_iocs_from_text("Running mimikatz.exe", "test", &mut iocs);
        assert!(iocs.iter().any(|i| i.ioc_type == "process" && i.value == "mimikatz.exe"));
    }

    #[test]
    fn test_ioc_extraction_service() {
        let mut iocs = Vec::new();
        extract_iocs_from_text("SERVICE_NAME: EvilSvc", "test", &mut iocs);
        assert!(iocs.iter().any(|i| i.ioc_type == "service" && i.value == "EvilSvc"));
    }

    #[test]
    fn test_report_format_roundtrip() {
        assert_eq!(ReportFormat::from_str("markdown"), ReportFormat::Markdown);
        assert_eq!(ReportFormat::from_str("json"), ReportFormat::Json);
        assert_eq!(ReportFormat::from_str("md"), ReportFormat::Markdown);
    }

    #[test]
    fn test_render_markdown_structure() {
        let data = ReportData {
            summary: ExecutiveSummary {
                campaign_name: "Test Campaign".to_string(),
                campaign_description: "A test".to_string(),
                total_sessions: 3,
                total_tasks: 10,
                successful_tasks: 8,
                failed_tasks: 2,
                unique_operators: 2,
                time_range_start: "2026-01-01".to_string(),
                time_range_end: "2026-01-31".to_string(),
            },
            timeline: vec![TimelineEntry {
                timestamp: 1706745600,
                operator: "alice".to_string(),
                session_hostname: "DC01".to_string(),
                task_type: "shell".to_string(),
                status: "COMPLETE".to_string(),
                result_summary: "NT AUTHORITY\\SYSTEM".to_string(),
            }],
            iocs: vec![Ioc {
                ioc_type: "ip".to_string(),
                value: "10.0.0.1".to_string(),
                context: "shell on DC01".to_string(),
            }],
            findings: vec!["Lateral movement via wmi succeeded on DC01".to_string()],
            recommendations: vec!["Segment network".to_string()],
        };

        let md = render_markdown(&data);
        assert!(md.contains("# SPECTER Engagement Report"));
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("Test Campaign"));
        assert!(md.contains("## Timeline of Actions"));
        assert!(md.contains("## Indicators of Compromise"));
        assert!(md.contains("## Findings"));
        assert!(md.contains("## Recommendations"));
    }

    #[test]
    fn test_render_json_structure() {
        let data = ReportData {
            summary: ExecutiveSummary {
                campaign_name: "Test".to_string(),
                campaign_description: String::new(),
                total_sessions: 0,
                total_tasks: 0,
                successful_tasks: 0,
                failed_tasks: 0,
                unique_operators: 0,
                time_range_start: "start".to_string(),
                time_range_end: "end".to_string(),
            },
            timeline: vec![],
            iocs: vec![],
            findings: vec![],
            recommendations: vec![],
        };

        let json = render_json(&data);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("timeline").is_some());
        assert!(parsed.get("iocs").is_some());
    }

    #[test]
    fn test_make_placeholders() {
        assert_eq!(make_placeholders(3), "?1, ?2, ?3");
        assert_eq!(make_placeholders(1), "?1");
    }

    #[test]
    fn test_format_timestamp_seconds() {
        let ts = 1706745600; // 2024-02-01 00:00:00 UTC
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2024"));
        assert!(formatted.contains("UTC"));
    }

    #[test]
    fn test_format_timestamp_millis() {
        let ts = 1706745600000i64;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2024"));
        assert!(formatted.contains("UTC"));
    }
}

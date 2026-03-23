// ──────────────────────────────────────────────────────────────────────
// End-to-end demo flow
// ──────────────────────────────────────────────────────────────────────
// Terminal 1 – Start the teamserver:
//   cargo run -p specter-server -- --dev-mode --http-port 8443 --grpc-port 50051
//
// Terminal 2 – Start the TUI client:
//   cargo run -p specter-client -- --dev-mode --server http://localhost:50051
//
// Terminal 3 – Run mock implants:
//   cargo run -p mock-implant -- --server http://127.0.0.1:8443 --count 3 --interval 5
//
// Expected: The TUI shows 3 sessions appearing with green ACTIVE status,
//           cycling through check-ins. Any queued tasks are dispatched to the
//           mock implants and mock results are returned on the next check-in.
// ──────────────────────────────────────────────────────────────────────

use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use specter_common::checkin::{CheckinRequest, CheckinResponse, TaskResultPayload};
use std::time::Duration;

/// Mock implant that simulates one or more implant check-ins against the
/// SPECTER teamserver HTTP listener.
#[derive(Parser, Debug)]
#[command(name = "mock-implant", about = "SPECTER mock implant for testing")]
struct Cli {
    /// Teamserver HTTP listener URL
    #[arg(long, default_value = "http://127.0.0.1:443")]
    server: String,

    /// Check-in interval in seconds
    #[arg(long, default_value_t = 10)]
    interval: u64,

    /// Jitter percentage (0-100)
    #[arg(long, default_value_t = 20)]
    jitter: u32,

    /// Number of mock implants to simulate
    #[arg(long, default_value_t = 1)]
    count: u32,

    /// Override hostname (only applies when count=1)
    #[arg(long)]
    hostname: Option<String>,

    /// Override username (only applies when count=1)
    #[arg(long)]
    username: Option<String>,
}

/// Metadata for a single simulated implant.
#[derive(Debug, Clone)]
struct ImplantMeta {
    hostname: String,
    username: String,
    pid: u32,
    os_version: String,
    integrity_level: String,
    process_name: String,
    internal_ip: String,
}

const HOSTNAMES: &[&str] = &[
    "DESKTOP-A7K3M2",
    "WORKSTATION-04",
    "SRV-DC01",
    "LAPTOP-R9B1X5",
    "DESKTOP-F3H8N6",
    "SRV-FILE02",
    "WORKSTATION-11",
    "LAPTOP-W2C4P7",
];

const USERNAMES: &[&str] = &[
    "jsmith",
    "admin",
    "svc_backup",
    "Administrator",
    "john.doe",
    "jane.doe",
    "svc_sql",
    "mwilson",
];

const OS_VERSIONS: &[&str] = &[
    "Windows 10 22H2",
    "Windows 11 23H2",
    "Windows Server 2019",
    "Windows Server 2022",
];

const INTEGRITY_LEVELS: &[&str] = &["Medium", "High", "SYSTEM"];

const PROCESS_NAMES: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "RuntimeBroker.exe",
    "notepad.exe",
    "msedge.exe",
    "powershell.exe",
];

fn generate_metadata(rng: &mut impl Rng) -> ImplantMeta {
    let hostname = HOSTNAMES[rng.gen_range(0..HOSTNAMES.len())].to_string();
    let username = USERNAMES[rng.gen_range(0..USERNAMES.len())].to_string();
    let pid = rng.gen_range(1000..65000);
    let os_version = OS_VERSIONS[rng.gen_range(0..OS_VERSIONS.len())].to_string();
    let integrity_level = INTEGRITY_LEVELS[rng.gen_range(0..INTEGRITY_LEVELS.len())].to_string();
    let process_name = PROCESS_NAMES[rng.gen_range(0..PROCESS_NAMES.len())].to_string();
    let internal_ip = if rng.gen_bool(0.5) {
        format!(
            "10.{}.{}.{}",
            rng.gen_range(0..255u8),
            rng.gen_range(1..255u8),
            rng.gen_range(1..255u8)
        )
    } else {
        format!(
            "192.168.{}.{}",
            rng.gen_range(1..255u8),
            rng.gen_range(1..255u8)
        )
    };

    ImplantMeta {
        hostname,
        username,
        pid,
        os_version,
        integrity_level,
        process_name,
        internal_ip,
    }
}

/// Generate a mock result for a given task type.
fn mock_task_result(task_type: &str, arguments: &str) -> String {
    match task_type {
        "execute_shell" | "shell" | "cmd" => {
            format!(
                "C:\\Windows\\system32>{arguments}\r\n\
                 Mock output for command: {arguments}\r\n\
                 Operation completed successfully."
            )
        }
        "list_files" | "ls" | "dir" => {
            format!(
                " Volume in drive C has no label.\r\n\
                 Directory of {arguments}\r\n\r\n\
                 03/15/2026  09:42 AM    <DIR>          .\r\n\
                 03/15/2026  09:42 AM    <DIR>          ..\r\n\
                 03/10/2026  02:15 PM             1,024 notes.txt\r\n\
                 03/12/2026  11:30 AM            32,768 report.docx\r\n\
                 03/14/2026  08:00 AM    <DIR>          Projects\r\n\
                                2 File(s)         33,792 bytes\r\n\
                                3 Dir(s)   48,123,456,512 bytes free"
            )
        }
        "whoami" => "DOMAIN\\jsmith".to_string(),
        "pwd" | "cwd" => "C:\\Users\\jsmith\\Desktop".to_string(),
        _ => format!("Command executed successfully: {task_type} {arguments}"),
    }
}

/// Compute a sleep duration with jitter applied.
fn jittered_sleep(base_secs: u64, jitter_pct: u32, rng: &mut impl Rng) -> Duration {
    if jitter_pct == 0 || base_secs == 0 {
        return Duration::from_secs(base_secs);
    }
    let jitter_range = (base_secs as f64) * (jitter_pct as f64 / 100.0);
    let delta = rng.gen_range(-jitter_range..=jitter_range);
    let actual = (base_secs as f64 + delta).max(1.0);
    Duration::from_secs_f64(actual)
}

/// Run a single mock implant check-in loop.
async fn run_implant(id: u32, server: String, meta: ImplantMeta, interval: u64, jitter: u32) {
    let client = reqwest::Client::new();
    let checkin_url = format!("{}/api/checkin", server.trim_end_matches('/'));
    let mut rng = StdRng::from_entropy();
    let mut session_id: Option<String> = None;
    let mut pending_results: Vec<TaskResultPayload> = Vec::new();

    println!(
        "[implant-{id}] Starting: {}\\{} (PID {}) on {} — checking in to {checkin_url}",
        meta.hostname, meta.username, meta.pid, meta.os_version
    );

    loop {
        let req = CheckinRequest {
            session_id: session_id.clone(),
            hostname: meta.hostname.clone(),
            username: meta.username.clone(),
            pid: meta.pid,
            os_version: meta.os_version.clone(),
            integrity_level: meta.integrity_level.clone(),
            process_name: meta.process_name.clone(),
            internal_ip: meta.internal_ip.clone(),
            external_ip: String::new(),
            task_results: std::mem::take(&mut pending_results),
        };

        match client.post(&checkin_url).json(&req).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<CheckinResponse>().await {
                        Ok(checkin_resp) => {
                            if session_id.is_none() {
                                println!(
                                    "[implant-{id}] Registered — session_id={}",
                                    checkin_resp.session_id
                                );
                            }
                            session_id = Some(checkin_resp.session_id);

                            if !checkin_resp.tasks.is_empty() {
                                println!(
                                    "[implant-{id}] Received {} task(s):",
                                    checkin_resp.tasks.len()
                                );
                            }
                            for task in &checkin_resp.tasks {
                                println!(
                                    "  → task_id={} type={} args={}",
                                    task.task_id, task.task_type, task.arguments
                                );
                                let result = mock_task_result(&task.task_type, &task.arguments);
                                pending_results.push(TaskResultPayload {
                                    task_id: task.task_id.clone(),
                                    status: "COMPLETE".to_string(),
                                    result,
                                });
                            }
                        }
                        Err(e) => {
                            eprintln!("[implant-{id}] Failed to parse response: {e}");
                        }
                    }
                } else {
                    eprintln!("[implant-{id}] Check-in returned status {}", resp.status());
                }
            }
            Err(e) => {
                eprintln!("[implant-{id}] Connection error: {e} — retrying next interval");
            }
        }

        let sleep_dur = jittered_sleep(interval, jitter, &mut rng);
        tokio::time::sleep(sleep_dur).await;
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.count == 0 {
        eprintln!("--count must be at least 1");
        std::process::exit(1);
    }

    let mut rng = rand::thread_rng();
    let mut handles = Vec::new();

    for i in 0..cli.count {
        let mut meta = generate_metadata(&mut rng);

        // Apply overrides for single implant mode
        if cli.count == 1 {
            if let Some(ref h) = cli.hostname {
                meta.hostname = h.clone();
            }
            if let Some(ref u) = cli.username {
                meta.username = u.clone();
            }
        }

        let server = cli.server.clone();
        let interval = cli.interval;
        let jitter = cli.jitter;

        // Stagger startup so implants don't all check in simultaneously
        let offset = if cli.count > 1 {
            Duration::from_millis(rng.gen_range(0..2000))
        } else {
            Duration::ZERO
        };

        handles.push(tokio::spawn(async move {
            tokio::time::sleep(offset).await;
            run_implant(i, server, meta, interval, jitter).await;
        }));
    }

    // Wait for all implants (they run forever until Ctrl-C)
    for h in handles {
        let _ = h.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_metadata_produces_valid_data() {
        let mut rng = rand::thread_rng();
        let meta = generate_metadata(&mut rng);
        assert!(!meta.hostname.is_empty());
        assert!(!meta.username.is_empty());
        assert!(meta.pid >= 1000 && meta.pid < 65000);
        assert!(!meta.os_version.is_empty());
        assert!(!meta.integrity_level.is_empty());
        assert!(!meta.process_name.is_empty());
        assert!(meta.internal_ip.starts_with("10.") || meta.internal_ip.starts_with("192.168."));
    }

    #[test]
    fn test_jittered_sleep_zero_jitter() {
        let mut rng = rand::thread_rng();
        let dur = jittered_sleep(10, 0, &mut rng);
        assert_eq!(dur, Duration::from_secs(10));
    }

    #[test]
    fn test_jittered_sleep_within_bounds() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let dur = jittered_sleep(10, 50, &mut rng);
            // 10 ± 50% → 5..15 seconds, but clamped to at least 1
            assert!(dur.as_secs_f64() >= 1.0);
            assert!(dur.as_secs_f64() <= 16.0);
        }
    }

    #[test]
    fn test_jittered_sleep_zero_base() {
        let mut rng = rand::thread_rng();
        let dur = jittered_sleep(0, 50, &mut rng);
        assert_eq!(dur, Duration::from_secs(0));
    }

    #[test]
    fn test_mock_task_result_shell() {
        let result = mock_task_result("execute_shell", "whoami");
        assert!(result.contains("whoami"));
        assert!(result.contains("Mock output"));
    }

    #[test]
    fn test_mock_task_result_dir() {
        let result = mock_task_result("list_files", "C:\\Users");
        assert!(result.contains("C:\\Users"));
        assert!(result.contains("Directory of"));
    }

    #[test]
    fn test_mock_task_result_unknown() {
        let result = mock_task_result("custom_task", "arg1");
        assert!(result.contains("custom_task"));
        assert!(result.contains("arg1"));
    }

    #[test]
    fn test_cli_defaults() {
        let cli = Cli::parse_from(["mock-implant"]);
        assert_eq!(cli.server, "http://127.0.0.1:443");
        assert_eq!(cli.interval, 10);
        assert_eq!(cli.jitter, 20);
        assert_eq!(cli.count, 1);
        assert!(cli.hostname.is_none());
        assert!(cli.username.is_none());
    }

    #[test]
    fn test_cli_custom_args() {
        let cli = Cli::parse_from([
            "mock-implant",
            "--server",
            "http://localhost:8443",
            "--interval",
            "5",
            "--jitter",
            "30",
            "--count",
            "3",
            "--hostname",
            "MYHOST",
            "--username",
            "testuser",
        ]);
        assert_eq!(cli.server, "http://localhost:8443");
        assert_eq!(cli.interval, 5);
        assert_eq!(cli.jitter, 30);
        assert_eq!(cli.count, 3);
        assert_eq!(cli.hostname, Some("MYHOST".to_string()));
        assert_eq!(cli.username, Some("testuser".to_string()));
    }
}

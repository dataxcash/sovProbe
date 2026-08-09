use sov_probe::wal::header::{encode_ip, WalRecord};

fn main() {
    let dir = std::env::args().nth(1).expect("usage: genwal_distinct <dir>");
    let segno: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    std::fs::create_dir_all(&dir).unwrap();
    let path = format!("{}/segment_{:04}.wal", dir, segno);
    let mut buf = Vec::new();
    for i in 0..200u32 {
        let payload = format!(
            "POST /api/orders/{} HTTP/1.1\r\nHost: seg{}-example.com\r\nContent-Length: 64\r\nX-Test: distinct-{}-{}\r\n\r\n{{}}",
            i, segno, segno, i
        ).into_bytes();
        let rec = WalRecord {
            timestamp_ns: 1_700_000_000_000 + segno * 1000 + i as u64,
            flags: 0,
            tcp_flags: 0x10,
            src_ip: encode_ip(Some([10, 0, 0, segno as u8]), None).0,
            dst_ip: encode_ip(Some([10, 0, 1, 1]), None).0,
            src_port: 10000 + segno as u16,
            dst_port: 8080,
            proto: 6,
            orig_payload_len: payload.len() as u32,
            payload,
        };
        rec.encode(&mut buf);
    }
    std::fs::write(&path, &buf).unwrap();
    println!("wrote {} bytes (200 records) to {}", buf.len(), path);
}

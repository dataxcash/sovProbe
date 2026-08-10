use sov_probe::wal::header::WalRecord;

/// 集成测试工具：生成一条标准 WAL（64B header v0.4 契约）供 slimSync 消费验证。
/// usage: genwal <dir>
fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: genwal <dir>"))?;
    std::fs::create_dir_all(&dir)?;
    let path = format!("{}/segment_0000.wal", dir);
    let mut buf = Vec::new();
    for i in 0..50u32 {
        let payload = format!(
            "GET /api/orders/{} HTTP/1.1\r\nHost: api.example.com\r\n",
            i
        )
        .into_bytes();
        let rec = WalRecord {
            timestamp_ns: 1_700_000_000_000 + i as u64,
            flags: 0,
            tcp_flags: 0x02, // SYN
            tcp_seq: 1000 + i,
            tcp_ack: 0,
            window_size: 65535,
            src_ip: [192, 168, 1, 10],
            dst_ip: [10, 0, 0, 1],
            src_port: 12345,
            dst_port: 443,
            proto: 6,
            orig_payload_len: payload.len() as u32,
            payload,
        };
        rec.encode(&mut buf);
    }
    std::fs::write(&path, &buf)?;
    println!("wrote {} bytes to {}", buf.len(), path);
    Ok(())
}

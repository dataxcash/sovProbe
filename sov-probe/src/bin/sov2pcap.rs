use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use sov_probe::wal::header::WalRecord;

/// sov2pcap — 离线 WAL → 标准 PCAP 转码工具。
///
/// 从 64B Header 恢复五元组、时间戳与**真实 TCP seq/ack/window**，合成
/// Ethernet + IPv4 + TCP/UDP 头，输出标准 .pcap（DataLink=ETHERNET），
/// 供 Wireshark / TShark / Suricata 做会话还原、REQ/RESP 匹配、丢包/乱序/RTT 分析。
#[derive(Parser, Debug)]
#[command(name = "sov2pcap", version, about)]
struct Cli {
    /// 单个 WAL 文件
    #[arg(long, short = 'i')]
    input: Option<String>,
    /// 目录内全部 WAL
    #[arg(long, short = 'd')]
    dir: Option<String>,
    /// 输出文件（单个输入时）
    #[arg(long, short = 'o')]
    output: Option<String>,
    /// 输出目录（批量时）
    #[arg(long, short = 'O')]
    out_dir: Option<String>,
    /// 按端口过滤（src 或 dst 匹配）
    #[arg(long)]
    filter_port: Option<u16>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let files: Vec<PathBuf> = if let Some(dir) = &cli.dir {
        let mut v = Vec::new();
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.extension().map(|x| x == "wal").unwrap_or(false) {
                v.push(p);
            }
        }
        v.sort();
        v
    } else if let Some(f) = &cli.input {
        vec![PathBuf::from(f)]
    } else {
        anyhow::bail!("需要 --input 或 --dir");
    };

    for f in files {
        let out = output_path(&cli, &f)?;
        let buf = std::fs::read(&f)?;
        let (records, residual) = WalRecord::decode_stream(&buf);
        if residual > 0 {
            eprintln!(
                "warn: {} 尾部残留 {} 字节（崩溃残块，已忽略）",
                f.display(),
                residual
            );
        }
        let file = std::fs::File::create(&out)?;
        let mut writer = PcapWriter::new(std::io::BufWriter::new(file))?;
        let mut n = 0usize;
        for rec in &records {
            if let Some(port) = cli.filter_port {
                if rec.dst_port != port && rec.src_port != port {
                    continue;
                }
            }
            let packet = synthesize(rec);
            let ts = Duration::from_nanos(rec.timestamp_ns);
            // incl_len = 实际落盘字节（packet.len()）
            // orig_len = orig_payload_len + L2(14) + L3(20) + L4(20/8)
            let l4_len = if rec.proto == 6 { 20 } else { 8 };
            let orig_len = 14 + 20 + l4_len + rec.orig_payload_len as usize;
            writer.write_packet(&PcapPacket::new(ts, orig_len as u32, &packet))?;
            n += 1;
        }
        drop(writer);
        println!("{} -> {} ({} packets)", f.display(), out.display(), n);
    }
    Ok(())
}

/// 输出路径：单文件用 -o，批量用 -O/<input>_converted.pcap
fn output_path(cli: &Cli, f: &Path) -> anyhow::Result<PathBuf> {
    if let Some(dir) = &cli.out_dir {
        std::fs::create_dir_all(dir)?;
        let name = f.file_stem().unwrap().to_string_lossy();
        return Ok(PathBuf::from(dir).join(format!("{name}.pcap")));
    }
    if let Some(out) = &cli.output {
        return Ok(PathBuf::from(out));
    }
    Ok(PathBuf::from(format!("{}.pcap", f.display())))
}

/// 合成一条完整帧：Ethernet + IPv4 + TCP/UDP + payload（v0.4 起仅 IPv4）。
/// 校验和置 0（Wireshark 自行计算）；seq/ack/window 填**真实线上值**。
fn synthesize(rec: &WalRecord) -> Vec<u8> {
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    let l4_len = (if rec.proto == 6 { 20 } else { 8 }) + rec.payload.len();

    let mut out = Vec::with_capacity(14 + 20 + l4_len);
    // Ethernet II
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&[0x08, 0x00]);

    // IPv4 头（20B）
    let total = 20 + l4_len;
    let (t_hi, t_lo) = (((total >> 8) & 0xFF) as u8, (total & 0xFF) as u8);
    out.extend_from_slice(&[0x45, 0x00, t_hi, t_lo]);
    out.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, rec.proto as u8, 0x00, 0x00]);
    out.extend_from_slice(&rec.src_ip);
    out.extend_from_slice(&rec.dst_ip);

    // TCP/UDP 传输层
    let (sp_hi, sp_lo) = ((rec.src_port >> 8) as u8, (rec.src_port & 0xFF) as u8);
    let (dp_hi, dp_lo) = ((rec.dst_port >> 8) as u8, (rec.dst_port & 0xFF) as u8);
    if rec.proto == 6 {
        // flags 字节 = 保留位(0) + 8 位 flags。我们的 u8 掩码即 TCP 头 byte13 的 flags 域。
        let flags = rec.tcp_flags;
        let (seq_b, ack_b) = (rec.tcp_seq.to_be_bytes(), rec.tcp_ack.to_be_bytes());
        let (win_hi, win_lo) = ((rec.window_size >> 8) as u8, (rec.window_size & 0xFF) as u8);
        out.extend_from_slice(&[
            sp_hi, sp_lo, dp_hi, dp_lo, // ports
            seq_b[0], seq_b[1], seq_b[2], seq_b[3], // seq（真实）
            ack_b[0], ack_b[1], ack_b[2], ack_b[3], // ack（真实）
            0x50, flags, win_hi, win_lo, 0, 0, 0, 0, // hlen + flags + window + checksum/urg
        ]);
    } else {
        let ulen = ((8 + rec.payload.len()) as u16).to_be_bytes();
        out.extend_from_slice(&[sp_hi, sp_lo, dp_hi, dp_lo, ulen[0], ulen[1], 0, 0]);
    }
    out.extend_from_slice(&rec.payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_probe::wal::header::TCP_ACK;
    use sov_probe::wal::header::TCP_SYN;

    fn record(proto: u16, tcp_flags: u8) -> WalRecord {
        WalRecord {
            timestamp_ns: 1_700_000_000_000,
            flags: 0,
            tcp_flags,
            tcp_seq: 0x1122_3344,
            tcp_ack: 0x5566_7788,
            window_size: 8192,
            src_ip: [192, 168, 1, 10],
            dst_ip: [10, 0, 0, 1],
            src_port: 12345,
            dst_port: 443,
            proto,
            orig_payload_len: 5,
            payload: b"hello".to_vec(),
        }
    }

    fn cli(output: Option<&str>, out_dir: Option<&str>) -> Cli {
        Cli {
            input: None,
            dir: None,
            output: output.map(String::from),
            out_dir: out_dir.map(String::from),
            filter_port: None,
        }
    }

    #[test]
    fn synthesize_tcp_ipv4_layout() {
        let rec = record(6, TCP_SYN | TCP_ACK);
        let packet = synthesize(&rec);
        let expect_len = 14 + 20 + (20 + rec.payload.len());
        assert_eq!(packet.len(), expect_len);
        // Ethernet II：dst_mac / src_mac / ethertype 0x0800
        assert_eq!(&packet[0..6], &[0x02, 0, 0, 0, 0, 2]);
        assert_eq!(&packet[6..12], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(&packet[12..14], &[0x08, 0x00]);
        // IPv4：IHL/version=0x45，protocol=6，地址正确
        assert_eq!(packet[14], 0x45);
        assert_eq!(packet[14 + 9], 6);
        assert_eq!(&packet[14 + 12..14 + 16], &[192, 168, 1, 10]);
        assert_eq!(&packet[14 + 16..14 + 20], &[10, 0, 0, 1]);
        // TCP：src/dst 端口，flags 字节保真（IPv4 头 20B + TCP 头内 offset 13）
        let tcp = 14 + 20;
        assert_eq!(&packet[tcp..tcp + 2], &[48, 57]); // 12345 BE
        assert_eq!(&packet[tcp + 2..tcp + 4], &[1, 187]); // 443 BE
        assert_eq!(packet[tcp + 13], TCP_SYN | TCP_ACK);
        // payload 尾部原样
        assert_eq!(&packet[expect_len - 5..], b"hello");
    }

    /// v0.4 核心：真实 seq/ack/window 必须落入 TCP 头（REQ/RESP 匹配 + RTT）。
    #[test]
    fn synthesize_tcp_preserves_seq_ack_window() {
        let rec = record(6, TCP_SYN | TCP_ACK);
        let packet = synthesize(&rec);
        let tcp = 14 + 20;
        // seq 字段 @tcp+4..+8，ack 字段 @tcp+8..+12
        assert_eq!(
            u32::from_be_bytes([packet[tcp + 4], packet[tcp + 5], packet[tcp + 6], packet[tcp + 7]]),
            rec.tcp_seq
        );
        assert_eq!(
            u32::from_be_bytes([packet[tcp + 8], packet[tcp + 9], packet[tcp + 10], packet[tcp + 11]]),
            rec.tcp_ack
        );
        // window 字段 @tcp+14..+16
        assert_eq!(
            u16::from_be_bytes([packet[tcp + 14], packet[tcp + 15]]),
            rec.window_size
        );
    }

    #[test]
    fn synthesize_udp_ipv4_layout() {
        let rec = record(17, 0);
        let packet = synthesize(&rec);
        let expect_len = 14 + 20 + (8 + rec.payload.len());
        assert_eq!(packet.len(), expect_len);
        assert_eq!(packet[14 + 9], 17);
        // UDP length 字段 = 8 + payload
        let udp = 14 + 20;
        let ulen = u16::from_be_bytes([packet[udp + 4], packet[udp + 5]]);
        assert_eq!(ulen, 8 + rec.payload.len() as u16);
    }

    #[test]
    fn output_path_single_file() {
        let c = cli(Some("/tmp/out.pcap"), None);
        let p = output_path(&c, Path::new("/tmp/a.wal")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/out.pcap"));
    }

    #[test]
    fn output_path_out_dir() {
        let c = cli(None, Some("/tmp/converted"));
        let p = output_path(&c, Path::new("/tmp/seg_0005.wal")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/converted/seg_0005.pcap"));
        let _ = std::fs::remove_dir_all("/tmp/converted");
    }

    #[test]
    fn output_path_default() {
        let c = cli(None, None);
        let p = output_path(&c, Path::new("/tmp/seg_0000.wal")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/seg_0000.wal.pcap"));
    }
}

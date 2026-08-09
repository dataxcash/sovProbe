use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use sov_probe::wal::header::{WalRecord, FLAG_IS_IPV6};

/// sov2pcap — 离线 WAL → 标准 PCAP 转码工具。
///
/// 从 64B Header 恢复五元组与时间戳，合成 Ethernet + IP + TCP/UDP 头，
/// 输出标准 .pcap（DataLink=ETHERNET），供 Wireshark / TShark / Suricata 分析。
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
            let orig_len = packet.len() as u32;
            writer.write_packet(&PcapPacket::new(ts, orig_len, &packet))?;
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

/// 合成一条完整帧：Ethernet + IPv4/IPv6 + TCP/UDP + payload。
/// 校验和置 0（Wireshark 自行计算）；TCP seq/ack 为合成占位。
fn synthesize(rec: &WalRecord) -> Vec<u8> {
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    let is_v6 = rec.flags & FLAG_IS_IPV6 != 0;
    let l4_len = (if rec.proto == 6 { 20 } else { 8 }) + rec.payload.len();

    let mut out = Vec::with_capacity(14 + if is_v6 { 40 } else { 20 } + l4_len);
    // Ethernet II
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(if is_v6 { &[0x86, 0xDD] } else { &[0x08, 0x00] });

    if is_v6 {
        // IPv6 头（40B）
        let plen = (l4_len as u16).to_be_bytes();
        out.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, plen[0], plen[1]]);
        out.push(rec.proto as u8); // next header
        out.push(0x40); // hop limit 64
        out.extend_from_slice(&rec.src_ip);
        out.extend_from_slice(&rec.dst_ip);
    } else {
        // IPv4 头（20B）
        let mut v4_src = [0u8; 4];
        let mut v4_dst = [0u8; 4];
        v4_src.copy_from_slice(&rec.src_ip[12..16]);
        v4_dst.copy_from_slice(&rec.dst_ip[12..16]);
        let total = 20 + l4_len;
        let (t_hi, t_lo) = (((total >> 8) & 0xFF) as u8, (total & 0xFF) as u8);
        out.extend_from_slice(&[0x45, 0x00, t_hi, t_lo]);
        out.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 0x40, rec.proto as u8, 0x00, 0x00]);
        out.extend_from_slice(&v4_src);
        out.extend_from_slice(&v4_dst);
    }

    // TCP/UDP 传输层
    let (sp_hi, sp_lo) = ((rec.src_port >> 8) as u8, (rec.src_port & 0xFF) as u8);
    let (dp_hi, dp_lo) = ((rec.dst_port >> 8) as u8, (rec.dst_port & 0xFF) as u8);
    if rec.proto == 6 {
        out.extend_from_slice(&[
            sp_hi, sp_lo, dp_hi, dp_lo, 0, 0, 0, 0, // seq
            0, 0, 0, 0, // ack
            0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0, // hlen/flags/window/checksum/urg
        ]);
    } else {
        let ulen = ((8 + rec.payload.len()) as u16).to_be_bytes();
        out.extend_from_slice(&[sp_hi, sp_lo, dp_hi, dp_lo, ulen[0], ulen[1], 0, 0]);
    }
    out.extend_from_slice(&rec.payload);
    out
}

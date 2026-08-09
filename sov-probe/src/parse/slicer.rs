use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

use crate::wal::header::{
    encode_ip, WalRecord, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG,
};

/// Payload Head-Slicer：零拷贝定位 L4 层，裁切应用层前 N 字节。
/// 保留 HTTP Header / JSON 根节点（够 AST/Schema 逆向），剔除大 Body。
/// v0.3：提取 TCP flags + orig_payload_len（原始线上长度）。
pub struct Slicer {
    /// 应用层裁切长度
    pub max_payload: usize,
}

impl Slicer {
    pub fn new(max_payload: usize) -> Self {
        Self { max_payload }
    }

    /// 将原始帧（含 Ethernet header）解析并裁切为一条 WAL 记录。
    /// 非 IP / 非 TCP/UDP / 截断 → None（不计入日志）。
    pub fn process(&self, frame: &[u8], ts_ns: u64, degraded: bool) -> Option<WalRecord> {
        let packet = SlicedPacket::from_ethernet(frame).ok()?;

        // IP 层：取 v4/v6 地址与协议
        let (src_v4, src_v6, dst_v4, dst_v6, is_v6, proto, transport) = match packet.ip {
            Some(InternetSlice::Ipv4(hdr, _)) => {
                let src = hdr.source_addr().octets();
                let dst = hdr.destination_addr().octets();
                (Some(src), None, Some(dst), None, false, hdr.protocol(), packet.transport)
            }
            Some(InternetSlice::Ipv6(hdr, _)) => {
                let src = hdr.source_addr().octets();
                let dst = hdr.destination_addr().octets();
                (None, Some(src), None, Some(dst), true, hdr.next_header(), packet.transport)
            }
            _ => return None,
        };

        // 传输层：TCP/UDP 才记录
        let (src_port, dst_port, tcp_flags, app) = match transport {
            Some(TransportSlice::Tcp(tcp)) => (
                tcp.source_port(),
                tcp.destination_port(),
                extract_tcp_flags(tcp),
                packet.payload,
            ),
            Some(TransportSlice::Udp(udp)) => {
                (udp.source_port(), udp.destination_port(), 0, packet.payload)
            }
            _ => return None,
        };

        let orig_payload_len = app.len() as u32;
        let truncated = app.len() > self.max_payload;
        let sliced = if truncated {
            app[..self.max_payload].to_vec()
        } else {
            app.to_vec()
        };

        let (src_enc, _) = encode_ip(src_v4, src_v6);
        let (dst_enc, _) = encode_ip(dst_v4, dst_v6);

        let mut flags = 0u64;
        if degraded {
            flags |= crate::wal::header::FLAG_DEGRADED;
        }
        if truncated {
            flags |= crate::wal::header::FLAG_TRUNCATED;
        }
        if is_v6 {
            flags |= crate::wal::header::FLAG_IS_IPV6;
        }

        Some(WalRecord {
            timestamp_ns: ts_ns,
            flags,
            tcp_flags,
            src_ip: src_enc,
            dst_ip: dst_enc,
            src_port,
            dst_port,
            proto: proto.into(),
            orig_payload_len,
            payload: sliced,
        })
    }
}

/// 提取 TCP flags 为独立 u8 位掩码（RFC 793：FIN/SYN/RST/PSH/ACK/URG）。
fn extract_tcp_flags(tcp: etherparse::TcpHeaderSlice) -> u8 {
    let mut f = 0u8;
    if tcp.fin() {
        f |= TCP_FIN;
    }
    if tcp.syn() {
        f |= TCP_SYN;
    }
    if tcp.rst() {
        f |= TCP_RST;
    }
    if tcp.psh() {
        f |= TCP_PSH;
    }
    if tcp.ack() {
        f |= TCP_ACK;
    }
    if tcp.urg() {
        f |= TCP_URG;
    }
    f
}

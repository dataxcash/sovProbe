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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::header::{FLAG_DEGRADED, FLAG_IS_IPV6, FLAG_TRUNCATED};
    use etherparse::PacketBuilder;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const SRC_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // 2001:db8::1
    const DST_V6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // fe80::1

    /// TCP over IPv4，SYN+ACK，payload 原样。
    fn tcp_v4_frame(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv4([192, 168, 1, 10], [10, 0, 0, 1], 64)
            .tcp(12345, 443, 100, 65535)
            .syn()
            .ack(50)
            .write(&mut buf, payload)
            .unwrap();
        buf
    }

    /// UDP over IPv4。
    fn udp_v4_frame(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv4([192, 168, 1, 10], [10, 0, 0, 1], 64)
            .udp(12345, 53)
            .write(&mut buf, payload)
            .unwrap();
        buf
    }

    /// TCP over IPv6。
    fn tcp_v6_frame(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv6(SRC_V6, DST_V6, 64)
            .tcp(80, 443, 100, 65535)
            .write(&mut buf, payload)
            .unwrap();
        buf
    }

    #[test]
    fn tcp_v4_slice_truncates_payload() {
        let payload = vec![0xAAu8; 100];
        let rec = Slicer::new(40).process(&tcp_v4_frame(&payload), 1234, false).unwrap();
        assert_eq!(rec.payload.len(), 40, "裁切到 max_payload");
        assert_eq!(rec.payload, payload[..40]);
        assert_eq!(rec.orig_payload_len, 100, "保留原始线上长度");
        assert_ne!(rec.flags & FLAG_TRUNCATED, 0);
    }

    #[test]
    fn tcp_v4_exact_boundary_not_truncated() {
        let payload = vec![0xBBu8; 40];
        let rec = Slicer::new(40).process(&tcp_v4_frame(&payload), 1, false).unwrap();
        assert_eq!(rec.payload, payload);
        assert_eq!(rec.flags & FLAG_TRUNCATED, 0);
    }

    #[test]
    fn tcp_v4_preserves_flags_ports_and_addr() {
        let rec = Slicer::new(4096).process(&tcp_v4_frame(b"GET / HTTP/1.1"), 999, false).unwrap();
        assert_eq!(rec.proto, 6);
        assert_eq!(rec.src_port, 12345);
        assert_eq!(rec.dst_port, 443);
        assert_eq!(rec.tcp_flags & TCP_SYN, TCP_SYN);
        assert_eq!(rec.tcp_flags & TCP_ACK, TCP_ACK);
        assert_eq!(rec.src_ip[12..16], [192, 168, 1, 10]);
        assert_eq!(rec.dst_ip[12..16], [10, 0, 0, 1]);
        assert_eq!(rec.src_ip[..12], [0u8; 12], "IPv4 高 12B 置 0");
        assert_eq!(rec.flags & FLAG_IS_IPV6, 0);
        assert_eq!(rec.timestamp_ns, 999);
    }

    #[test]
    fn udp_v4_has_no_tcp_flags() {
        let rec = Slicer::new(4096).process(&udp_v4_frame(b"query"), 5, false).unwrap();
        assert_eq!(rec.proto, 17);
        assert_eq!(rec.tcp_flags, 0, "UDP 无 TCP flags");
        assert_eq!(rec.dst_port, 53);
    }

    #[test]
    fn ipv6_tcp_sets_v6_flag_and_full_addr() {
        let rec = Slicer::new(4096)
            .process(&tcp_v6_frame(b"v6"), 7, false)
            .unwrap();
        assert_ne!(rec.flags & FLAG_IS_IPV6, 0);
        assert_eq!(rec.src_ip, SRC_V6, "IPv6 16B 全量保留");
        assert_eq!(rec.dst_ip, DST_V6);
        assert_eq!(rec.src_port, 80);
        assert_eq!(rec.dst_port, 443);
    }

    #[test]
    fn rejects_non_ip_frame() {
        // ARP 帧：Ethernet 头 + ethertype 0x0806，无 IP 层
        let frame = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst mac
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src mac
            0x08, 0x06, // ethertype ARP
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        ];
        assert!(Slicer::new(4096).process(&frame, 0, false).is_none());
    }

    #[test]
    fn rejects_non_tcp_udp_transport() {
        // ICMP echo request：IP 协议号 1，非 TCP/UDP
        let mut frame = Vec::new();
        PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv4([192, 168, 1, 10], [10, 0, 0, 1], 64)
            .icmpv4_echo_request(1, 2)
            .write(&mut frame, b"ping")
            .unwrap();
        assert!(Slicer::new(4096).process(&frame, 0, false).is_none());
    }

    #[test]
    fn garbage_returns_none() {
        assert!(Slicer::new(4096).process(&[0x00, 0x01, 0x02, 0x03], 0, false).is_none());
        assert!(Slicer::new(4096).process(&[], 0, false).is_none());
    }

    #[test]
    fn degraded_sets_flag() {
        let rec = Slicer::new(4096).process(&tcp_v4_frame(b"x"), 1, true).unwrap();
        assert_ne!(rec.flags & FLAG_DEGRADED, 0);
    }

    #[test]
    fn v4_truncated_record_is_roundtrip_consistent() {
        // 裁切后编码 → 解码，TRUNCATED 由 orig_len > payload_len 隐式还原
        let payload = vec![0xCCu8; 200];
        let rec = Slicer::new(64).process(&tcp_v4_frame(&payload), 42, false).unwrap();
        let mut buf = Vec::new();
        rec.encode(&mut buf);
        let (decoded, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(residual, 0);
        assert_eq!(decoded.len(), 1);
        assert_ne!(decoded[0].flags & FLAG_TRUNCATED, 0);
        assert_eq!(decoded[0].payload.len(), 64);
        assert_eq!(decoded[0].orig_payload_len, 200);
    }
}

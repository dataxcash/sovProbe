use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

use crate::wal::header::{
    WalRecord, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG,
};

/// Payload Head-Slicer：零拷贝定位 L4 层，裁切应用层前 N 字节。
/// 保留 HTTP Header / JSON 根节点（够 AST/Schema 逆向），剔除大 Body。
/// v0.4：提取真实 TCP seq/ack/window（REQ/RESP 匹配、丢包/乱序/RTT 分析）。
/// 仅捕获 IPv4（v0.4 契约砍原生 IPv6）。
pub struct Slicer {
    /// 应用层裁切长度
    pub max_payload: usize,
}

impl Slicer {
    pub fn new(max_payload: usize) -> Self {
        Self { max_payload }
    }

    /// 将原始帧（含 Ethernet header）解析并裁切为一条 WAL 记录。
    /// 非 IPv4 / 非 TCP/UDP / 截断 → None（不计入日志）。
    pub fn process(&self, frame: &[u8], ts_ns: u64, degraded: bool) -> Option<WalRecord> {
        let packet = SlicedPacket::from_ethernet(frame).ok()?;

        // IP 层：仅 IPv4（v0.4 起 IPv6 帧不记录）
        let (src_ip, dst_ip, proto) = match &packet.ip {
            Some(InternetSlice::Ipv4(hdr, _)) => {
                let src = hdr.source_addr().octets();
                let dst = hdr.destination_addr().octets();
                (src, dst, hdr.protocol())
            }
            _ => return None,
        };

        // 传输层：TCP/UDP 才记录
        let (src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, window_size, app) =
            transport_header(&packet)?;

        let orig_payload_len = app.len() as u32;
        let truncated = app.len() > self.max_payload;
        let sliced = if truncated {
            app[..self.max_payload].to_vec()
        } else {
            app.to_vec()
        };

        let mut flags = 0u64;
        if degraded {
            flags |= crate::wal::header::FLAG_DEGRADED;
        }
        if truncated {
            flags |= crate::wal::header::FLAG_TRUNCATED;
        }

        Some(WalRecord {
            timestamp_ns: ts_ns,
            flags,
            tcp_flags,
            tcp_seq,
            tcp_ack,
            window_size,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto: proto.into(),
            orig_payload_len,
            payload: sliced,
        })
    }
}

/// 传输层提取结果：端口对、TCP flags、真实 seq/ack/window、应用层 payload。
/// UDP 无 seq/ack/window → 全 0。
type TransportMeta<'a> = (u16, u16, u8, u32, u32, u16, &'a [u8]);

/// 传输层头提取：返回 (src_port, dst_port, flags, seq, ack, window, app_payload)。
fn transport_header<'a>(packet: &'a SlicedPacket<'a>) -> Option<TransportMeta<'a>> {
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => Some((
            tcp.source_port(),
            tcp.destination_port(),
            extract_tcp_flags(tcp.clone()),
            tcp.sequence_number(),
            tcp.acknowledgment_number(),
            tcp.window_size(),
            packet.payload,
        )),
        Some(TransportSlice::Udp(udp)) => {
            Some((udp.source_port(), udp.destination_port(), 0, 0, 0, 0, packet.payload))
        }
        _ => None,
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
    use crate::wal::header::{FLAG_DEGRADED, FLAG_TRUNCATED};
    use etherparse::PacketBuilder;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    /// TCP over IPv4，SYN+ACK，seq=100 ack=50 window=65535，payload 原样。
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
        assert_eq!(rec.src_ip, [192, 168, 1, 10], "v0.4 起 IPv4 原生 4B");
        assert_eq!(rec.dst_ip, [10, 0, 0, 1]);
        assert_eq!(rec.timestamp_ns, 999);
    }

    /// v0.4 核心：真实 TCP seq/ack/window 必须保真（REQ/RESP 匹配 + RTT）。
    #[test]
    fn tcp_v4_preserves_seq_ack_window() {
        let rec = Slicer::new(4096)
            .process(&tcp_v4_frame(b"GET /api HTTP/1.1"), 1, false)
            .unwrap();
        assert_eq!(rec.tcp_seq, 100);
        assert_eq!(rec.tcp_ack, 50);
        assert_eq!(rec.window_size, 65535);
    }

    #[test]
    fn udp_v4_zeroed_tcp_fields() {
        let rec = Slicer::new(4096).process(&udp_v4_frame(b"query"), 5, false).unwrap();
        assert_eq!(rec.proto, 17);
        assert_eq!(rec.tcp_flags, 0, "UDP 无 TCP flags");
        assert_eq!(rec.tcp_seq, 0);
        assert_eq!(rec.tcp_ack, 0);
        assert_eq!(rec.window_size, 0);
        assert_eq!(rec.dst_port, 53);
    }

    /// v0.4 契约：IPv6 帧不记录（返回 None）。
    #[test]
    fn ipv6_frame_rejected_in_v04() {
        let src: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut frame = Vec::new();
        PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv6(src, dst, 64)
            .tcp(80, 443, 1, 65535)
            .write(&mut frame, b"v6")
            .unwrap();
        assert!(
            Slicer::new(4096).process(&frame, 7, false).is_none(),
            "v0.4 仅 IPv4，IPv6 帧应丢弃"
        );
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

    /// 用户态热路径吞吐基准（CPU 侧能力，可复现）：slicer 解析 + WAL 编码。
    /// 不含内核 ringbuf / 通道 / 磁盘写——用于量化单核热路径包速率上限，
    /// 并作为回归护栏防止后续优化回退。数值随机器波动，只打印不设硬断言。
    #[test]
    fn hot_path_userspace_throughput() {
        let payload = vec![0xAAu8; 512];
        let frame = tcp_v4_frame(&payload);
        let slicer = Slicer::new(4096);
        let n = 300_000u64;
        let mut scratch = Vec::new();
        let mut checksum: u64 = 0;

        // 预热：让分配器/CRC 常数表就位
        for _ in 0..10_000 {
            if let Some(rec) = slicer.process(&frame, 1, false) {
                scratch.clear();
                rec.encode(&mut scratch);
            }
        }
        scratch.clear();

        let t0 = std::time::Instant::now();
        for i in 0..n {
            if let Some(rec) = slicer.process(&frame, i, false) {
                scratch.clear();
                rec.encode(&mut scratch);
                checksum = checksum.wrapping_add(rec.payload.len() as u64);
            }
        }
        let dt = t0.elapsed().as_secs_f64();
        let pps = n as f64 / dt;
        eprintln!(
            "userspace hot path (slicer+encode, 512B payload): {:.0} pps ({:.2} Mpps), {:.2} us/rec",
            pps,
            pps / 1e6,
            dt * 1e6 / n as f64
        );
        // 200k pps 是本探针设计压测点；纯用户态热路径应显著高于此，
        // 否则瓶颈在解析/编码本身（与内核捕获无关）。
        assert!(pps > 200_000.0, "hot path too slow: {:.0} pps", pps);
        assert!(checksum > 0);
    }
}

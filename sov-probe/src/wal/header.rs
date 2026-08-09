use byteorder::{BigEndian, ByteOrder};

/// WAL 记录头契约（v0.3）：固定 64 字节，`repr(C)`，严格按评审给定的物理布局。
///
/// ```text
/// Offset  Size  Field             Type / 说明
/// 0       2     magic             u16 = 0x5350 ("SP")
/// 2       1     version           u8 = 0x03
/// 3       1     tcp_flags         u8 (FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20)
/// 4       4     crc32             u32 覆盖 [magic+tcp_flags+timestamp..orig_len 全部 + payload]
/// 8       8     timestamp_ns      u64 大端，纳秒
/// 16      16    src_ip            [u8;16] IPv4 高12B=0 低4B=大端 / IPv6 原样
/// 32      16    dst_ip            [u8;16] 同上
/// 48      2     src_port          u16 大端
/// 50      2     dst_port          u16 大端
/// 52      1     proto             u8 (6=TCP, 17=UDP)
/// 53      3     reserved_pad      [u8;3]  bit0=DEGRADED bit1=IS_IPV6
/// 56      4     payload_len       u32 裁切后实际落盘长度 (incl_len)
/// 60      4     orig_payload_len  u32 线上原始长度 (orig_len)
/// ─────────────────────────────────────────
/// 64 字节定长，无 padding
/// ```
///
/// 语义推导（不占物理位的派生值）：
/// - TRUNCATED = orig_payload_len > payload_len（隐式，不存位）
/// - DEGRADED  = reserved_pad[0] bit0
/// - IS_IPV6   = reserved_pad[0] bit1
///
/// CRC32 覆盖范围：header 除 crc32 字段(4..8)外的全部字节 + 全部 payload。
pub const WAL_HEADER_SIZE: usize = 64;
pub const WAL_VERSION: u8 = 0x03;
pub const WAL_MAGIC: u16 = 0x5350; // "SP"

// TCP flags（RFC 793 位定义）
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

// 逻辑 flags（编码/解码时映射到 reserved_pad 位）
pub const FLAG_DEGRADED: u64 = 1 << 0;
pub const FLAG_TRUNCATED: u64 = 1 << 1; // 派生：orig_payload_len > payload_len
pub const FLAG_IS_IPV6: u64 = 1 << 2;

/// 解码后的记录（逻辑视图，非磁盘布局）。
#[derive(Debug, Clone)]
pub struct WalRecord {
    pub timestamp_ns: u64,
    pub flags: u64,
    pub tcp_flags: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u16,
    pub orig_payload_len: u32,
    pub payload: Vec<u8>,
}

impl WalRecord {
    /// 将记录编码为 64B header + payload 字节序列。
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(start + WAL_HEADER_SIZE, 0);
        {
            let h = &mut out[start..start + WAL_HEADER_SIZE];
            BigEndian::write_u16(&mut h[0..2], WAL_MAGIC);
            h[2] = WAL_VERSION;
            h[3] = self.tcp_flags;
            // 4..8 crc32 占位，写完 payload 后回填
            BigEndian::write_u64(&mut h[8..16], self.timestamp_ns);
            h[16..32].copy_from_slice(&self.src_ip);
            h[32..48].copy_from_slice(&self.dst_ip);
            BigEndian::write_u16(&mut h[48..50], self.src_port);
            BigEndian::write_u16(&mut h[50..52], self.dst_port);
            h[52] = self.proto as u8;
            // reserved_pad[0] 位映射
            h[53] = 0;
            if self.flags & FLAG_DEGRADED != 0 {
                h[53] |= 0x01;
            }
            if self.flags & FLAG_IS_IPV6 != 0 {
                h[53] |= 0x02;
            }
            // 53..56 其余 pad 保持 0
            BigEndian::write_u32(&mut h[56..60], self.payload.len() as u32);
            BigEndian::write_u32(&mut h[60..64], self.orig_payload_len);
        }

        // payload
        out.extend_from_slice(&self.payload);

        // CRC32 覆盖 header 除 crc32 字段 + payload，回填
        let crc = crc32_of(&out[start..]);
        let h = &mut out[start..start + WAL_HEADER_SIZE];
        BigEndian::write_u32(&mut h[4..8], crc);
    }

    /// 三重校验解析（Magic -> Length -> CRC32）。任意一步失败返回 None（脏尾丢弃）。
    pub fn try_decode(buf: &[u8], pos: usize) -> Option<(WalRecord, usize)> {
        if buf.len() - pos < WAL_HEADER_SIZE {
            return None; // 连 header 都不足 → 残段
        }
        let h = &buf[pos..pos + WAL_HEADER_SIZE];

        // ① Magic 校验
        if BigEndian::read_u16(&h[0..2]) != WAL_MAGIC {
            return None;
        }

        // ② Length 校验
        let payload_len = BigEndian::read_u32(&h[56..60]) as usize;
        let total = WAL_HEADER_SIZE + payload_len;
        if buf.len() - pos < total {
            return None;
        }

        // ③ CRC32 校验
        let expected = BigEndian::read_u32(&h[4..8]);
        let actual = crc32_of(&buf[pos..pos + total]);
        if actual != expected {
            return None;
        }

        let orig_len = BigEndian::read_u32(&h[60..64]);
        let mut flags = 0u64;
        if orig_len > payload_len as u32 {
            flags |= FLAG_TRUNCATED;
        }
        if h[53] & 0x01 != 0 {
            flags |= FLAG_DEGRADED;
        }
        if h[53] & 0x02 != 0 {
            flags |= FLAG_IS_IPV6;
        }

        let record = WalRecord {
            timestamp_ns: BigEndian::read_u64(&h[8..16]),
            flags,
            tcp_flags: h[3],
            src_ip: h[16..32].try_into().unwrap(),
            dst_ip: h[32..48].try_into().unwrap(),
            src_port: BigEndian::read_u16(&h[48..50]),
            dst_port: BigEndian::read_u16(&h[50..52]),
            proto: h[52] as u16,
            orig_payload_len: orig_len,
            payload: buf[pos + WAL_HEADER_SIZE..pos + total].to_vec(),
        };
        Some((record, pos + total))
    }

    /// 流式重组：从字节流中解析出所有完整记录。
    /// 返回 (records, 剩余残段字节数)。供 SovVault 端 / sov2pcap 使用。
    pub fn decode_stream(buf: &[u8]) -> (Vec<WalRecord>, usize) {
        let mut records = Vec::new();
        let mut pos = 0usize;
        while let Some((rec, next)) = Self::try_decode(buf, pos) {
            records.push(rec);
            pos = next;
        }
        (records, buf.len() - pos)
    }
}

/// CRC32：覆盖 header 除 crc32 字段(4..8)外的全部字节 + payload。
/// 编码与解码均跳过 crc32 字段，保证不受字段内已存值影响。
fn crc32_of(buf: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    // buf[0..4] = magic/version/tcp_flags
    hasher.update(&buf[0..4]);
    // 跳过 buf[4..8] crc32 字段
    hasher.update(&buf[8..]);
    hasher.finalize()
}

/// IPv4/IPv6 统一编码：16B 数组。IPv4 → 低 4B 大端，高 12B 置 0。
#[inline]
pub fn encode_ip(ipv4: Option<[u8; 4]>, ipv6: Option<[u8; 16]>) -> ([u8; 16], u64) {
    if let Some(v6) = ipv6 {
        (v6, FLAG_IS_IPV6)
    } else if let Some(v4) = ipv4 {
        let mut out = [0u8; 16];
        out[12..16].copy_from_slice(&v4);
        (out, 0)
    } else {
        ([0u8; 16], 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> WalRecord {
        WalRecord {
            timestamp_ns: 1_700_000_000_123,
            flags: 0,
            tcp_flags: TCP_SYN | TCP_ACK,
            src_ip: encode_ip(Some([192, 168, 1, 10]), None).0,
            dst_ip: encode_ip(Some([10, 0, 0, 1]), None).0,
            src_port: 12345,
            dst_port: 443,
            proto: 6,
            orig_payload_len: 1000,
            payload: b"GET /api HTTP/1.1".to_vec(),
        }
    }

    fn encode_to_buf(rec: &WalRecord) -> Vec<u8> {
        let mut buf = Vec::new();
        rec.encode(&mut buf);
        buf
    }

    #[test]
    fn header_roundtrip_v03() {
        let rec = sample_record();
        let buf = encode_to_buf(&rec);
        assert_eq!(buf.len(), WAL_HEADER_SIZE + rec.payload.len());
        // magic + version
        assert_eq!(BigEndian::read_u16(&buf[0..2]), WAL_MAGIC);
        assert_eq!(buf[2], WAL_VERSION);
        let (records, _residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.timestamp_ns, rec.timestamp_ns);
        assert_eq!(r.src_ip[12..16], [192, 168, 1, 10]);
        assert_eq!(r.dst_port, 443);
        assert_eq!(r.tcp_flags, TCP_SYN | TCP_ACK);
        assert_eq!(r.orig_payload_len, 1000);
        assert_eq!(r.payload, rec.payload);
        // 截断推导：orig 1000 > payload 22 → TRUNCATED 置位
        assert_ne!(r.flags & FLAG_TRUNCATED, 0);
    }

    /// ① 坏 Magic → 丢弃
    #[test]
    fn reject_bad_magic() {
        let rec = sample_record();
        let mut buf = encode_to_buf(&rec);
        buf[0] ^= 0xFF;
        let (records, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 0);
        assert_eq!(residual, buf.len());
    }

    /// ② 坏 Length（payload_len 撕裂偏大）→ 残段丢弃
    #[test]
    fn reject_bad_length() {
        let rec = sample_record();
        let mut buf = encode_to_buf(&rec);
        BigEndian::write_u32(&mut buf[56..60], 0xFFFF_FFFF);
        let (records, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 0);
        assert_eq!(residual, buf.len());
    }

    /// ③ CRC32 不匹配（payload 中间损坏）→ 丢弃
    #[test]
    fn reject_crc_mismatch() {
        let rec = sample_record();
        let mut buf = encode_to_buf(&rec);
        buf[WAL_HEADER_SIZE + 5] ^= 0x40;
        let (records, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 0);
        assert_eq!(residual, buf.len());
    }

    /// 多记录 + 损坏混合：完好记录保留，损坏记录丢弃
    #[test]
    fn mixed_valid_and_corrupt() {
        let rec1 = sample_record();
        let rec2 = sample_record();
        let mut buf = Vec::new();
        rec1.encode(&mut buf);
        rec2.encode(&mut buf);
        let off2 = (WAL_HEADER_SIZE + rec1.payload.len()) + WAL_HEADER_SIZE;
        buf[off2 + 3] ^= 0xFF;
        let (records, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 1);
        assert!(residual >= WAL_HEADER_SIZE + rec2.payload.len());
    }

    /// 残段（不足一条）→ 返回残段字节数
    #[test]
    fn decode_stream_residual() {
        let rec = sample_record();
        let mut buf = encode_to_buf(&rec);
        buf.truncate(buf.len() - 20);
        let (records, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 0);
        assert_eq!(residual, buf.len());
    }
}

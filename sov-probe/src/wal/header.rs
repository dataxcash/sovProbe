use byteorder::{BigEndian, ByteOrder};

/// WAL 记录头契约（v0.2）：固定 64 字节定长，64-byte cache line 对齐。
///
/// 布局（全部大端序）：
/// ```text
/// Offset  Size  Field            Type
/// 0       8     timestamp_ns     u64
/// 8       8     flags            u64 (bit0=degraded, bit1=truncated, bit2=is_ipv6)
/// 16      16    src_ip           [u8;16]  IPv4: 高 12B=0，低 4B=大端 IPv4
/// 32      16    dst_ip           [u8;16]  同上
/// 48      2     src_port         u16
/// 50      2     dst_port         u16
/// 52      2     proto            u16 (6=TCP, 17=UDP)
/// 54      4     payload_len      u32
/// 58      6     reserved         [u8;6]
/// ```
pub const WAL_HEADER_SIZE: usize = 64;

pub const FLAG_DEGRADED: u64 = 1 << 0;
pub const FLAG_TRUNCATED: u64 = 1 << 1;
pub const FLAG_IS_IPV6: u64 = 1 << 2;

/// 解码后的记录，供 WAL 遍历 / SovVault 重组解析使用。
#[derive(Debug, Clone)]
pub struct WalRecord {
    pub timestamp_ns: u64,
    pub flags: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u16,
    pub payload: Vec<u8>,
}

impl WalRecord {
    /// 将 64B header + payload 编码为磁盘字节序列。
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.resize(start + WAL_HEADER_SIZE, 0);
        let h = &mut out[start..start + WAL_HEADER_SIZE];
        BigEndian::write_u64(&mut h[0..8], self.timestamp_ns);
        BigEndian::write_u64(&mut h[8..16], self.flags);
        h[16..32].copy_from_slice(&self.src_ip);
        h[32..48].copy_from_slice(&self.dst_ip);
        BigEndian::write_u16(&mut h[48..50], self.src_port);
        BigEndian::write_u16(&mut h[50..52], self.dst_port);
        BigEndian::write_u16(&mut h[52..54], self.proto);
        BigEndian::write_u32(&mut h[54..58], self.payload.len() as u32);
        // reserved[58..64] 保持 0
        out.extend_from_slice(&self.payload);
    }

    /// 尝试从 buf 的 pos 处解析一条记录；不足一条时返回 None（残段需等下一个 Chunk）。
    /// 返回 (record, 下一记录起始偏移)。
    /// 注：该 API 供 SovVault 端流式重组（Stream Reassembly）使用；sovProbe 仅写不读。
    #[allow(dead_code)]
    pub fn try_decode(buf: &[u8], pos: usize) -> Option<(WalRecord, usize)> {
        if buf.len() - pos < WAL_HEADER_SIZE {
            return None;
        }
        let h = &buf[pos..pos + WAL_HEADER_SIZE];
        let payload_len = BigEndian::read_u32(&h[54..58]) as usize;
        let total = WAL_HEADER_SIZE + payload_len;
        if buf.len() - pos < total {
            return None;
        }
        let record = WalRecord {
            timestamp_ns: BigEndian::read_u64(&h[0..8]),
            flags: BigEndian::read_u64(&h[8..16]),
            src_ip: h[16..32].try_into().unwrap(),
            dst_ip: h[32..48].try_into().unwrap(),
            src_port: BigEndian::read_u16(&h[48..50]),
            dst_port: BigEndian::read_u16(&h[50..52]),
            proto: BigEndian::read_u16(&h[52..54]),
            payload: buf[pos + WAL_HEADER_SIZE..pos + total].to_vec(),
        };
        Some((record, pos + total))
    }

    /// 流式重组：从字节流中解析出所有完整记录。
    /// 返回 (records, 剩余残段字节数)。供 SovVault 端使用。
    #[allow(dead_code)]
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

/// IPv4/IPv6 统一编码：16B 数组。
/// IPv4 → 低 4B 为大端地址，高 12B 置 0。
/// IPv6 → 直接 16B 原样。
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

    #[test]
    fn header_roundtrip() {
        let rec = WalRecord {
            timestamp_ns: 1_700_000_000_123,
            flags: 0,
            src_ip: encode_ip(Some([192, 168, 1, 10]), None).0,
            dst_ip: encode_ip(Some([10, 0, 0, 1]), None).0,
            src_port: 12345,
            dst_port: 443,
            proto: 6,
            payload: b"GET /api HTTP/1.1".to_vec(),
        };
        let mut buf = Vec::new();
        rec.encode(&mut buf);
        assert_eq!(buf.len(), WAL_HEADER_SIZE + rec.payload.len());
        let (records, _residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.timestamp_ns, rec.timestamp_ns);
        assert_eq!(r.src_ip[12..16], [192, 168, 1, 10]);
        assert_eq!(r.dst_port, 443);
        assert_eq!(r.payload, rec.payload);
    }

    #[test]
    fn decode_stream_residual() {
        let rec1 = WalRecord {
            timestamp_ns: 1,
            flags: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 1,
            dst_port: 2,
            proto: 6,
            payload: vec![0xAA; 100],
        };
        let mut buf = Vec::new();
        rec1.encode(&mut buf);
        // 截断成残段：去掉最后 20 字节
        buf.truncate(buf.len() - 20);
        let (records, residual) = WalRecord::decode_stream(&buf);
        assert_eq!(records.len(), 0);
        assert_eq!(residual, buf.len());
    }
}

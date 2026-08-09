use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;
use slim_common::framing::{
    decode_chunk_frame, decode_seal_frame, CHUNK_FRAME_HEADER_LEN, ChunkFrame, SealFrame,
};
use sov_probe::wal::header::WalRecord;
use tokio::sync::Mutex;

/// sub_save_test — M7 E2E 接收端测试工具（缺陷 #7 修正版）。
///
/// 订阅 slim/sync/chunks/**（数据）与 slim/sync/segments/**（封盘信号）。
/// 每个 Chunk 帧头部携带 `(dev_id, segment_seq, start_offset)`，接收端按
/// 段序号分组、按段内绝对 offset 幂等落位重组（不依赖到达顺序，容忍乱序/去重引用），
/// 封盘信号到达后对该段做三重校验（Magic -> Length -> CRC32）并落盘 segment_XXXX.wal。
///
/// 落盘产物为源段原始字节流，可直接与 /dev/shm/sov-probe 源段做 md5 对账。
#[derive(Parser, Debug)]
#[command(name = "sub_save_test", version, about)]
struct Cli {
    /// Zenoh 数据订阅主题（默认全量 chunks）
    #[arg(long, default_value = "slim/sync/chunks/**")]
    topic: String,
    /// Zenoh 段封盘信号订阅主题
    #[arg(long, default_value = "slim/sync/segments/**")]
    seal_topic: String,
    /// 输出目录（重组后的 WAL 落盘）
    #[arg(long, default_value = "/data/reassembled")]
    out: String,
    /// 32B 解密密钥（hex，与 slimSync key_file 一致）
    #[arg(long)]
    key_hex: String,
    /// 统计周期（秒）
    #[arg(long, default_value = "5")]
    stat_secs: u64,
    /// 监听端点（如 tcp/0.0.0.0:7447），作为 peer/listener 接受连接
    #[arg(long)]
    listen: Option<String>,
}

/// 单个逻辑段的字节重组缓冲：按 offset 幂等落位 + 连续水位推进。
struct SegmentBuf {
    file: Option<File>,
    path: PathBuf,
    /// 已连续写入字节数（= 文件当前大小，源段追加写 ⇒ 字节流天然连续）
    next_expected: u64,
    /// 乱序到达/未达的 Chunk：offset -> bytes
    pending: BTreeMap<u64, Vec<u8>>,
    /// 插桩：pending 滞留字节数（预算执行依据）
    pending_bytes: u64,
    /// 已收到封盘信号
    sealed: bool,
    /// 封盘时对账出的缺失字节数
    missing_on_seal: u64,
    records: u64,
    residual: u64,
    /// 插桩：已实际落位的 chunk 帧数（含顺序写 + pending 回填）
    placed_chunks: u64,
    /// 插桩：因 offset<next_expected 被幂等丢弃的帧数（重复到达）
    dup_dropped: u64,
}

impl SegmentBuf {
    /// dev_id==1 保持 `segment_XXXX.wal`（M7 单探针对账契约）；
    /// 多探针（dev_id!=1）使用 `dev{dev_id}_segment_XXXX.wal` 隔离，避免串段。
    fn seg_path(dev_id: u32, seq: u32, out_dir: &Path) -> PathBuf {
        if dev_id == 1 {
            out_dir.join(format!("segment_{:04}.wal", seq))
        } else {
            out_dir.join(format!("dev{}_segment_{:04}.wal", dev_id, seq))
        }
    }

    fn open(dev_id: u32, seq: u32, out_dir: &Path) -> Self {
        let path = Self::seg_path(dev_id, seq, out_dir);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        // 断点续传：已有文件视为已连续写满，从现有尺寸继续
        let next_expected = file.as_ref().and_then(|_| path.metadata().ok()).map(|m| m.len()).unwrap_or(0);
        SegmentBuf {
            file,
            path,
            next_expected,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            sealed: false,
            missing_on_seal: 0,
            records: 0,
            residual: 0,
            placed_chunks: 0,
            dup_dropped: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        if let Some(f) = self.file.as_mut() {
            let _ = f.write_all(bytes);
            // 性能：不在每个 chunk 上 fsync（高吞吐下 3000+/s 的 flush 是消费端最大瓶颈），
            // 数据由 OS page cache 承载，封盘/退出时统一 flush。
        }
        self.next_expected += bytes.len() as u64;
    }

    /// 落位一个 Chunk（按绝对 offset）。返回是否落位成功。
    fn place(&mut self, offset: u64, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        if offset < self.next_expected {
            self.dup_dropped += 1; // 插桩：已覆盖（重复 / 幂等兜底）
            return false;
        }
        if offset > self.next_expected {
            // 乱序 / 空洞：暂存，待水位推进后回填
            self.pending.insert(offset, bytes.to_vec());
            self.pending_bytes += bytes.len() as u64;
            return true;
        }
        // 顺序到达：直接写，随后回填 pending
        self.write_bytes(bytes);
        self.placed_chunks += 1;
        loop {
            match self.pending.iter().next() {
                Some((&o, _)) if o == self.next_expected => {
                    let b = self.pending.remove(&o).unwrap();
                    self.pending_bytes -= b.len() as u64;
                    self.write_bytes(&b);
                    self.placed_chunks += 1;
                }
                _ => break,
            }
        }
        true
    }

    /// 封盘：flush + 三重校验统计。返回缺失字节数。
    fn on_seal(&mut self, sealed_size: u64) -> u64 {
        self.sealed = true;
        if let Some(f) = self.file.as_mut() {
            let _ = f.flush();
        }
        let missing = sealed_size.saturating_sub(self.next_expected);
        self.missing_on_seal = missing;
        // 三重校验对账（对账用，不破坏原始字节）
        if let Ok(bytes) = std::fs::read(&self.path) {
            let (records, residual) = WalRecord::decode_stream(&bytes);
            self.records = records.len() as u64;
            self.residual = residual as u64;
        }
        missing
    }
}

/// 全局重组器
struct Reassembler {
    out_dir: PathBuf,
    /// 按 (dev_id, segment_seq) 分组，多探针隔离不串段
    segments: HashMap<(u32, u32), SegmentBuf>,
    /// 去重引用物化缓存：blind_id -> 明文 Chunk 字节（有界，超预算逐出最旧）。
    /// 被逐出条目使 EXISTS 应答降为 false → 发送端改发数据帧，正确性不受影响。
    blind_cache: HashMap<[u8; 16], Vec<u8>>,
    /// blind 插入顺序（FIFO 逐出用）
    blind_order: std::collections::VecDeque<[u8; 16]>,
    blind_cache_bytes: u64,
    blind_cache_evicted: u64,
    total_chunks: u64,
    total_refs: u64,
    total_bytes: u64,
    unframed_dropped: u64,
    cache_miss: u64,
    gaps: u64,
    sealed_segments: u64,
    /// 插桩：每个 (dev_id, segment_seq) 已送达订阅层的 chunk 帧数（解码成功即计）
    frames_by_segment: HashMap<(u32, u32), u64>,
    /// 插桩：pending 超预算被逐出的滞留 chunk 数（内存安全网触发计数）
    pend_dropped: u64,
}

/// 去重引用物化缓存预算（字节）：超出则逐出最旧，保证接收端内存有界。
const BLIND_CACHE_BUDGET: u64 = 64 * 1024 * 1024;

/// pending（乱序/空洞滞留）总字节预算：超出则逐出全局最旧滞留项并记账。
/// 防止 REF_ONLY 逐出竞态或偶发传输缺口导致 pending 无界增长（实测曾到 448MB+）。
/// 正常全量数据帧模式下 pending 仅短暂滞留乱序帧，此预算为安全网。
const PENDING_BUDGET: u64 = 256 * 1024 * 1024;

impl Reassembler {
    fn new(out_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&out_dir).unwrap();
        Reassembler {
            out_dir,
            segments: HashMap::new(),
            blind_cache: HashMap::new(),
            blind_order: std::collections::VecDeque::new(),
            blind_cache_bytes: 0,
            blind_cache_evicted: 0,
            total_chunks: 0,
            total_refs: 0,
            total_bytes: 0,
            unframed_dropped: 0,
            cache_miss: 0,
            gaps: 0,
            sealed_segments: 0,
            frames_by_segment: HashMap::new(),
            pend_dropped: 0,
        }
    }

    /// 插入缓存并在超预算时逐出最旧（FIFO）。逐出只影响去重命中率，不影响正确性。
    fn cache_insert(&mut self, blind_id: [u8; 16], bytes: Vec<u8>) {
        let len = bytes.len() as u64;
        if let Some(old) = self.blind_cache.insert(blind_id, bytes) {
            self.blind_cache_bytes -= old.len() as u64;
        } else {
            self.blind_order.push_back(blind_id);
        }
        self.blind_cache_bytes += len;
        while self.blind_cache_bytes > BLIND_CACHE_BUDGET {
            match self.blind_order.pop_front() {
                Some(oldest) => {
                    if let Some(v) = self.blind_cache.remove(&oldest) {
                        self.blind_cache_bytes -= v.len() as u64;
                        self.blind_cache_evicted += 1;
                    }
                }
                None => break,
            }
        }
    }

    /// 从 topic key 解析 blind_id（最后一段 32 hex）。
    fn blind_id_from_key(key: &str) -> Option<[u8; 16]> {
        let hex_str = key.rsplit('/').next().filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))?;
        let bytes = hex::decode(hex_str).ok()?;
        bytes.try_into().ok()
    }

    /// 处理一个数据/引用帧。
    fn on_chunk_frame(&mut self, key: &str, payload: Vec<u8>, cipher_key: &[u8; 32]) {
        let frame = match decode_chunk_frame(&payload) {
            Some(f) => f,
            None => {
                self.unframed_dropped += 1;
                tracing::warn!("unframed payload dropped (key={})", key);
                return;
            }
        };

        let blind_id = Self::blind_id_from_key(key);
        self.total_chunks += 1;
        *self
            .frames_by_segment
            .entry((frame.dev_id, frame.segment_seq))
            .or_insert(0) += 1;

        let plaintext: Vec<u8> = if frame.ref_only {
            self.total_refs += 1;
            match blind_id.and_then(|id| self.blind_cache.get(&id).cloned()) {
                Some(b) => b,
                None => {
                    self.cache_miss += 1;
                    tracing::warn!("REF_ONLY frame with missing blind cache (key={})", key);
                    return;
                }
            }
        } else {
            let cipher = &payload[CHUNK_FRAME_HEADER_LEN..];
            match decrypt(cipher_key, cipher) {
                Some(p) => {
                    if let Some(id) = blind_id {
                        self.cache_insert(id, p.clone());
                    }
                    p
                }
                None => {
                    tracing::warn!("decrypt failed / malformed chunk (key={})", key);
                    return;
                }
            }
        };

        if (plaintext.len() as u32) != frame.chunk_len {
            tracing::warn!(
                "chunk len mismatch: header={} actual={} (key={})",
                frame.chunk_len,
                plaintext.len(),
                key
            );
        }
        self.place(frame, &plaintext);
    }

    fn place(&mut self, frame: ChunkFrame, plaintext: &[u8]) {
        self.total_bytes += plaintext.len() as u64;
        let key = (frame.dev_id, frame.segment_seq);
        let buf = self
            .segments
            .entry(key)
            .or_insert_with(|| SegmentBuf::open(frame.dev_id, frame.segment_seq, &self.out_dir));
        buf.place(frame.start_offset, plaintext);
        self.enforce_pending_budget();
    }

    /// pending 总量超出预算时，逐出全局最旧滞留项（最小 offset），直至回落到预算内。
    /// 逐出的数据段会留下缺口，由封盘 SEAL 对账上报；换取接收端内存有界。
    fn enforce_pending_budget(&mut self) {
        while self.pending_total() > PENDING_BUDGET {
            let victim: Option<(u32, u32)> = self
                .segments
                .iter()
                .filter(|(_, b)| !b.pending.is_empty())
                .min_by_key(|(_, b)| *b.pending.keys().next().unwrap())
                .map(|(k, _)| *k);
            match victim {
                Some(key) => {
                    if let Some(buf) = self.segments.get_mut(&key) {
                        if let Some((_, bytes)) = buf.pending.pop_first() {
                            buf.pending_bytes -= bytes.len() as u64;
                            self.pend_dropped += 1;
                        }
                    }
                }
                None => break,
            }
        }
    }

    fn pending_total(&self) -> u64 {
        self.segments.values().map(|b| b.pending_bytes).sum()
    }

    /// 处理封盘信号。
    fn on_seal_frame(&mut self, seal: SealFrame) {
        self.sealed_segments += 1;
        let key = (seal.dev_id, seal.segment_seq);
        match self.segments.get_mut(&key) {
            Some(buf) => {
                let missing = buf.on_seal(seal.sealed_size);
                if missing > 0 {
                    self.gaps += 1;
                }
                if buf.next_expected > seal.sealed_size {
                    // 现有文件比封盘声明的尺寸还大 → 疑似旧会话残留文件污染（断点续传误续水位）
                    tracing::warn!(
                        "SEAL dev={} seg={} 现有文件({}B) 大于封盘尺寸({}B)——疑为残留旧文件，需清空 out 目录重跑",
                        seal.dev_id,
                        seal.segment_seq,
                        buf.next_expected,
                        seal.sealed_size
                    );
                }
                let first_pend_off = buf.pending.keys().next().copied().unwrap_or(0);
                let pend_gap = first_pend_off.saturating_sub(buf.next_expected);
                tracing::info!(
                    "SEAL dev={} seg={} size={} got={} missing={} records={} residual={} placed_chunks={} pended_chunks={} pend_bytes={} dup_dropped={} recv_frames={} first_pend_off={} pend_gap={}",
                    seal.dev_id,
                    seal.segment_seq,
                    seal.sealed_size,
                    buf.next_expected,
                    missing,
                    buf.records,
                    buf.residual,
                    buf.placed_chunks,
                    buf.pending.len(),
                    buf.pending_bytes,
                    buf.dup_dropped,
                    self.frames_by_segment.get(&key).copied().unwrap_or(0),
                    first_pend_off,
                    pend_gap
                );
            }
            None => {
                // 从未收到该段任何 Chunk 的封盘信号：仅记账，不落盘空文件
                tracing::warn!(
                    "SEAL for unknown dev={} seg={} (size={}) — 该段数据未到达",
                    seal.dev_id,
                    seal.segment_seq,
                    seal.sealed_size
                );
            }
        }
    }

    /// 回答 EXISTS 盲去重查询：仅当字节已在本地缓存时才回 "true"。
    fn has_blind(&self, blind_id: [u8; 16]) -> bool {
        self.blind_cache.contains_key(&blind_id)
    }

    fn stats(&self) -> String {
        format!(
            "chunks={} refs={} bytes={} unframed={} cache_miss={} gaps={} sealed={} active_segments={} cache_bytes={} evicted={} pend_bytes={} pend_dropped={}",
            self.total_chunks,
            self.total_refs,
            self.total_bytes,
            self.unframed_dropped,
            self.cache_miss,
            self.gaps,
            self.sealed_segments,
            self.segments.len(),
            self.blind_cache_bytes,
            self.blind_cache_evicted,
            self.pending_total(),
            self.pend_dropped,
        )
    }

    fn flush_all(&mut self) {
        for buf in self.segments.values_mut() {
            if let Some(f) = buf.file.as_mut() {
                let _ = f.flush();
            }
        }
        tracing::info!("shutdown: {}", self.stats());
    }
}

fn decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place(nonce, &[], &mut plaintext)
        .ok()?;
    Some(plaintext)
}

#[tokio::main]
async fn main() -> Result<()> {
    // 默认 info 级日志（兼容 RUST_LOG 覆盖），避免未设环境变量时日志静默
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let cli = Cli::parse();

    let key_bytes = hex::decode(&cli.key_hex)?;
    if key_bytes.len() != 32 {
        anyhow::bail!("key_hex 必须为 32 字节（64 hex 字符）");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let mut zcfg = zenoh::Config::default();
    if let Some(ep) = &cli.listen {
        let _ = zcfg.insert_json5("listen/endpoints", &format!("[\"{}\"]", ep));
        tracing::info!("zenoh listen: {ep}");
    }
    let session = zenoh::open(zcfg)
        .await
        .map_err(|e| anyhow::anyhow!("zenoh open: {e}"))?;

    let reassembler = Arc::new(Mutex::new(Reassembler::new(PathBuf::from(&cli.out))));
    let out_dir = PathBuf::from(&cli.out);

    // ── 数据订阅 ──
    let sub_reassembler = reassembler.clone();
    let sub = session
        .declare_subscriber(&cli.topic)
        .await
        .map_err(|e| anyhow::anyhow!("declare_subscriber {}: {e}", cli.topic))?;
    tracing::info!("subscribed: {} -> {}", cli.topic, out_dir.display());
    let data_key = key;
    tokio::spawn(async move {
        while let Ok(sample) = sub.recv_async().await {
            let key_expr = sample.key_expr().to_string();
            let payload: Vec<u8> = sample.payload().to_bytes().into();
            let mut r = sub_reassembler.lock().await;
            r.on_chunk_frame(&key_expr, payload, &data_key);
        }
    });

    // ── 封盘信号订阅 ──
    let seal_reassembler = reassembler.clone();
    let seal_sub = session
        .declare_subscriber(&cli.seal_topic)
        .await
        .map_err(|e| anyhow::anyhow!("declare_subscriber {}: {e}", cli.seal_topic))?;
    tracing::info!("subscribed: {}", cli.seal_topic);
    tokio::spawn(async move {
        while let Ok(sample) = seal_sub.recv_async().await {
            let payload: Vec<u8> = sample.payload().to_bytes().into();
            if let Some(seal) = decode_seal_frame(&payload) {
                let mut r = seal_reassembler.lock().await;
                r.on_seal_frame(seal);
            }
        }
    });

    // ── 盲去重 EXISTS 查询应答（支持 slimSync 去重引用帧） ──
    let exists_reassembler = reassembler.clone();
    let queryable = session
        .declare_queryable(&format!("{}/**", slim_common::topics::EXISTS))
        .await
        .map_err(|e| anyhow::anyhow!("declare_queryable: {e}"))?;
    tracing::info!("queryable: {}", slim_common::topics::EXISTS);
    tokio::spawn(async move {
        while let Ok(query) = queryable.recv_async().await {
            let key = query.key_expr().to_string();
            if let Some(id) = Reassembler::blind_id_from_key(&key) {
                let exists = {
                    let r = exists_reassembler.lock().await;
                    r.has_blind(id)
                };
                let reply = if exists { "true".to_string() } else { "false".to_string() };
                // ReplyBuilder 必须 .await 才会真正发送应答
                let _ = query.reply(query.key_expr().clone(), reply.as_bytes()).await;
            }
        }
    });

    // ── 周期统计 ──
    let stat_interval = Duration::from_secs(cli.stat_secs);
    let stat_reassembler = reassembler.clone();
    let stat_task = tokio::spawn(async move {
        let mut last = Instant::now();
        loop {
            tokio::time::sleep(stat_interval).await;
            let r = stat_reassembler.lock().await;
            let per_sec = {
                let now = Instant::now();
                let dt = now.duration_since(last).as_secs_f64().max(1e-9);
                last = now;
                r.total_bytes as f64 / dt
            };
            tracing::info!("STAT {} rate={:.0}B/s", r.stats(), per_sec);
        }
    });

    tokio::signal::ctrl_c().await?;
    tracing::info!("ctrl-c received, finalizing...");
    stat_task.abort();
    {
        let mut r = reassembler.lock().await;
        r.flush_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use slim_common::framing::{encode_chunk_frame, encode_seal_frame};

    fn tmp_out(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sub_save_test_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key() -> [u8; 32] {
        [0x11; 32]
    }

    /// 加密（nonce 固定 + ChaCha20），与生产 decrypt 对称。
    fn enc(data: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key()));
        let mut nonce = [0u8; 12];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut ct = data.to_vec();
        cipher.encrypt_in_place(Nonce::from_slice(&nonce), &[], &mut ct).unwrap();
        [nonce.as_slice(), ct.as_slice()].concat()
    }

    fn frame(seg: u32, offset: u64, data: &[u8]) -> Vec<u8> {
        encode_chunk_frame(1, seg, offset, data.len() as u32, &enc(data), false)
    }

    fn blind_key(prefix: &[u8; 16]) -> String {
        format!("slim/sync/chunks/{}", hex::encode(prefix))
    }

    /// 顺序落位 + 乱序落位（offset 先大后小）→ 字节流按 offset 正确重组。
    #[test]
    fn place_in_order_and_out_of_order() {
        let dir = tmp_out("order");
        let mut r = Reassembler::new(dir.clone());
        // 乱序：先到 offset 5 的块（比 0 大，进 pending）
        r.on_chunk_frame(
            &blind_key(b"aaaaaaaaaaaaaaaa"),
            frame(3, 5, b"world"),
            &key(),
        );
        // 顺序：offset 0 → 触发回填 offset 5
        r.on_chunk_frame(&blind_key(b"bbbbbbbbbbbbbbbb"), frame(3, 0, b"hello"), &key());
        // 去重幂等：重复 offset 0
        r.on_chunk_frame(&blind_key(b"bbbbbbbbbbbbbbbb"), frame(3, 0, b"hello"), &key());
        let bytes = std::fs::read(dir.join("segment_0003.wal")).unwrap();
        assert_eq!(bytes, b"helloworld");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 乱序块：到达时 offset > 水位 → 暂存，水位推进后回填；文件字节完整。
    #[test]
    fn out_of_order_backfill() {
        let dir = tmp_out("backfill");
        let mut r = Reassembler::new(dir.clone());
        // 先来 offset=6 的块（应进 pending）
        r.on_chunk_frame(&blind_key(b"aaaaaaaaaaaaaaaa"), frame(0, 6, b"data"), &key());
        // 再来 offset=0..6 的块 → 触发回填
        r.on_chunk_frame(&blind_key(b"bbbbbbbbbbbbbbbb"), frame(0, 0, b"prefix"), &key());
        let bytes = std::fs::read(dir.join("segment_0000.wal")).unwrap();
        assert_eq!(bytes, b"prefixdata");
        assert!(r.segments[&(1, 0)].pending.is_empty(), "pending 应已清空");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 封盘缺失对账：空洞未填 → 报缺失字节数。
    #[test]
    fn seal_reports_missing_gap() {
        let dir = tmp_out("gap");
        let mut r = Reassembler::new(dir.clone());
        r.on_chunk_frame(&blind_key(b"cccccccccccccccc"), frame(2, 0, b"0123456789"), &key());
        r.on_seal_frame(SealFrame { dev_id: 1, segment_seq: 2, sealed_size: 25 });
        assert_eq!(r.segments[&(1, 2)].missing_on_seal, 15, "应报缺失 15 字节");
        assert_eq!(r.gaps, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 封盘三重校验对账：完整 WAL 段 → records 数正确、residual=0。
    #[test]
    fn seal_counts_records() {
        use sov_probe::wal::header::{encode_ip, WalRecord, TCP_ACK};
        let dir = tmp_out("records");
        let mut r = Reassembler::new(dir.clone());
        let mut wal = Vec::new();
        for i in 0..3u32 {
            let rec = WalRecord {
                timestamp_ns: 1_700_000_000_000 + i as u64,
                flags: 0,
                tcp_flags: TCP_ACK,
                src_ip: encode_ip(Some([10, 0, 0, 1]), None).0,
                dst_ip: encode_ip(Some([10, 0, 0, 2]), None).0,
                src_port: 1000,
                dst_port: 8080,
                proto: 6,
                orig_payload_len: 4,
                payload: b"req!".to_vec(),
            };
            rec.encode(&mut wal);
        }
        let seg = 1u32;
        let third = wal.len() / 3;
        // 乱序 3 块发布（2/3 处 → 0 → 1/3 处），验证按 offset 重组后解码正确
        r.on_chunk_frame(&blind_key(b"aaaaaaaaaaaaaaaa"), frame(seg, (third * 2) as u64, &wal[third * 2..]), &key());
        r.on_chunk_frame(&blind_key(b"bbbbbbbbbbbbbbbb"), frame(seg, 0, &wal[..third]), &key());
        r.on_chunk_frame(&blind_key(b"cccccccccccccccc"), frame(seg, third as u64, &wal[third..third * 2]), &key());
        r.on_seal_frame(SealFrame { dev_id: 1, segment_seq: seg, sealed_size: wal.len() as u64 });
        assert_eq!(r.gaps, 0);
        let out = std::fs::read(dir.join("segment_0001.wal")).unwrap();
        assert_eq!(out, wal, "重组字节应与源 WAL 完全一致");
        let buf = r.segments.get(&(1, seg)).unwrap();
        assert_eq!(buf.records, 3);
        assert_eq!(buf.residual, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 去重引用帧：数据帧先进缓存 → 引用帧物化成功；缺缓存 → cache_miss 计数。
    #[test]
    fn ref_only_materialization() {
        let dir = tmp_out("ref");
        let mut r = Reassembler::new(dir.clone());
        let key_expr = format!("slim/sync/chunks/{}", hex::encode([0xdd; 16]));
        // 先发数据帧（入缓存 + 落位）
        r.on_chunk_frame(&key_expr, frame(5, 0, b"secret"), &key());
        // 引用帧（另一 segment 复用）→ 从缓存物化
        r.on_chunk_frame(&key_expr, encode_chunk_frame(1, 6, 0, 6, b"", true), &key());
        let seg5 = std::fs::read(dir.join("segment_0005.wal")).unwrap();
        let seg6 = std::fs::read(dir.join("segment_0006.wal")).unwrap();
        assert_eq!(seg5, b"secret");
        assert_eq!(seg6, b"secret");
        assert_eq!(r.total_refs, 1);
        assert_eq!(r.cache_miss, 0);
        // 未知 blind_id 的引用帧 → cache_miss
        let miss_key = format!("slim/sync/chunks/{}", hex::encode([0xee; 16]));
        r.on_chunk_frame(&miss_key, encode_chunk_frame(1, 7, 0, 6, b"", true), &key());
        assert_eq!(r.cache_miss, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_frame_parse_roundtrip() {
        let framed = encode_seal_frame(7, 42, 65536);
        let seal = decode_seal_frame(&framed).unwrap();
        assert_eq!(seal.dev_id, 7);
        assert_eq!(seal.segment_seq, 42);
        assert_eq!(seal.sealed_size, 65536);
    }

    /// 多探针隔离：dev_id=1 与 dev_id=2 同段号不得串段（各自独立落盘）。
    #[test]
    fn dev_id_isolation() {
        let dir = tmp_out("dev");
        let mut r = Reassembler::new(dir.clone());
        // dev1 seg0
        r.on_chunk_frame(
            &blind_key(b"aaaaaaaaaaaaaaaa"),
            encode_chunk_frame(1, 0, 0, 4, &enc(b"dev1"), false),
            &key(),
        );
        // dev2 seg0（同段号，不同探针）
        r.on_chunk_frame(
            &blind_key(b"bbbbbbbbbbbbbbbb"),
            encode_chunk_frame(2, 0, 0, 4, &enc(b"dev2"), false),
            &key(),
        );
        let dev1 = std::fs::read(dir.join("segment_0000.wal")).unwrap();
        let dev2 = std::fs::read(dir.join("dev2_segment_0000.wal")).unwrap();
        assert_eq!(dev1, b"dev1");
        assert_eq!(dev2, b"dev2");
        assert_eq!(r.segments.len(), 2, "两探针必须独立分组");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

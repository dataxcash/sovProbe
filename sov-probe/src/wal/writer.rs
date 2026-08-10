use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;

use super::header::WalRecord;
use super::rotate::Rotator;
use crate::guard::breaker::Breaker;

/// WalWriter 构造参数聚合（避免 8 参数过长的 `new`）。
#[derive(Clone)]
pub struct WriterParams {
    pub shm_path: String,
    pub max_segments: usize,
    pub segment_size: u64,
    pub rotate_interval: Duration,
    pub breaker: Breaker,
    pub queue_watermark: u8,
    pub written_records: Arc<AtomicU64>,
    pub dropped_records: Arc<AtomicU64>,
}

/// SHM Ring-WAL Writer：追加写 64B header + payload，定长/定时双轮转，
/// Ring-Overwrite 强制覆盖，写满 drop-tail（绝不阻塞）。
pub struct WalWriter {
    rotator: Rotator,
    segment_size: u64,
    rotate_interval: Duration,
    file: Option<BufWriter<File>>,
    current_path: std::path::PathBuf,
    written: u64,
    next_rotate: Instant,
    breaker: Breaker,
    queue_watermark: u8,
    /// 共享计数（metrics 读取）
    pub written_records: Arc<AtomicU64>,
    pub dropped_records: Arc<AtomicU64>,
}

impl WalWriter {
    pub fn new(params: WriterParams) -> anyhow::Result<Self> {
        fs::create_dir_all(&params.shm_path)?;
        let rotator = Rotator::new(&params.shm_path, params.max_segments)?;
        Ok(Self {
            rotator,
            segment_size: params.segment_size,
            rotate_interval: params.rotate_interval,
            file: None,
            current_path: std::path::PathBuf::new(),
            written: 0,
            next_rotate: Instant::now() + params.rotate_interval,
            breaker: params.breaker,
            queue_watermark: params.queue_watermark,
            written_records: params.written_records,
            dropped_records: params.dropped_records,
        })
    }

    fn open_segment(&mut self) -> anyhow::Result<()> {
        let path = self.rotator.next_segment()?;
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        self.file = Some(BufWriter::new(f));
        self.current_path = path;
        self.written = 0;
        self.next_rotate = Instant::now() + self.rotate_interval;
        Ok(())
    }

    /// 消费通道中的记录并落盘。
    /// degraded 时丢弃（Drop-Tail），fail-open。
    ///
    /// TC-3 实测缺陷修复：原实现 `rx.recv()` 阻塞等待，洪泛结束后通道排空，
    /// writer 卡在 recv 上不再迭代 → `hot_path_check` 永不再执行 → `degraded`
    /// 永久锁死 true（降级后永不恢复）。改用 `recv_timeout(200ms)`：空闲时
    /// 周期唤醒执行水位检查，队列回落到一半以下即自动恢复。
    pub fn run(&mut self, rx: &Receiver<WalRecord>) -> anyhow::Result<()> {
        if self.file.is_none() {
            self.open_segment()?;
        }
        loop {
            // 热路径水位检查（writer 侧持有 Receiver，可查 len）
            self.breaker.hot_path_check(rx, self.queue_watermark);
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(record) => {
                    self.handle_record(record)?;
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(_) => break, // 所有 sender 关闭
            }
            self.maybe_rotate()?;
        }
        self.flush()?;
        Ok(())
    }

    /// 单条记录处理：degraded → 丢弃；否则编码写入，超限强制覆盖轮转。
    fn handle_record(&mut self, record: WalRecord) -> anyhow::Result<()> {
        if self.breaker.is_degraded() {
            self.dropped_records.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let mut buf = Vec::with_capacity(super::header::WAL_HEADER_SIZE + record.payload.len());
        record.encode(&mut buf);
        let total = buf.len() as u64;

        // 超 segment 上限 → 先强制覆盖轮转（Ring-Overwrite），再写新段
        if self.written + total > self.segment_size {
            self.flush()?;
            self.open_segment()?;
        }
        if let Some(f) = self.file.as_mut() {
            f.write_all(&buf)?;
            self.written += total;
            self.written_records.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn maybe_rotate(&mut self) -> anyhow::Result<()> {
        if Instant::now() >= self.next_rotate && self.written > 0 {
            self.flush()?;
            self.open_segment()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.flush()?;
        }
        Ok(())
    }

    /// 关闭时 flush 并落盘。
    #[allow(dead_code)]
    pub fn shutdown(&mut self) -> anyhow::Result<()> {
        self.flush()
    }
}

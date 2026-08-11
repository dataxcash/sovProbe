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
    /// 复用编码缓冲：热路径每记录 1 次分配 → 0 次（capacity 保持，clear 复用）
    scratch: Vec<u8>,
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
            scratch: Vec::new(),
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
        // 复用 scratch 缓冲：clear 不释放 capacity，编码不产生堆分配
        self.scratch.clear();
        self.scratch
            .reserve(super::header::WAL_HEADER_SIZE + record.payload.len());
        record.encode(&mut self.scratch);
        let total = self.scratch.len() as u64;

        // 超 segment 上限 → 先强制覆盖轮转（Ring-Overwrite），再写新段
        if self.written + total > self.segment_size {
            self.flush()?;
            self.open_segment()?;
        }
        if let Some(f) = self.file.as_mut() {
            f.write_all(&self.scratch)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::slicer::Slicer;
    use crossbeam_channel::bounded;

    /// 合成 TCP/IPv4 帧（512B payload）。
    fn tcp_v4_frame() -> Vec<u8> {
        let payload = vec![0xAAu8; 512];
        let mut buf = Vec::new();
        etherparse::PacketBuilder::ethernet2(
            [0x02, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 2],
        )
        .ipv4([192, 168, 1, 10], [10, 0, 0, 1], 64)
        .tcp(12345, 443, 100, 65535)
        .syn()
        .write(&mut buf, &payload)
        .unwrap();
        buf
    }

    /// 全链路用户态吞吐基准：Slicer → bounded channel → WalWriter（真实写 tmpfs）。
    ///
    /// 与 hot_path_userspace_throughput（仅 parse+encode）对照：
    /// - 若本值接近上者 → 通道/写盘不是瓶颈，瓶颈在 aya ringbuf 消费（内核侧）；
    /// - 若本值显著更低 → 瓶颈在 channel/WalWriter 交付路径，可继续内省。
    ///
    /// 输出 pps 只打印不硬断言（防机器间抖动）。
    #[test]
    fn full_pipeline_throughput_bench() {
        const N: u64 = 200_000;
        let dir = std::env::temp_dir().join(format!("sovprobe_pipe_bench_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let breaker = Breaker::new();
        let written = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, rx) = bounded::<WalRecord>(1_000_000); // 容量 >> N，基准期间永不触及水位
        let rx = Arc::new(rx);

        let mut writer = WalWriter::new(WriterParams {
            shm_path: dir.to_string_lossy().into_owned(),
            max_segments: 8,
            segment_size: 256 * 1024 * 1024,
            rotate_interval: Duration::from_secs(3600),
            breaker: breaker.clone(),
            queue_watermark: 100, // 基准测满速，禁用降级丢帧
            written_records: written.clone(),
            dropped_records: dropped.clone(),
        })
        .unwrap();

        let frame = tcp_v4_frame();
        let slicer = Slicer::new(4096);
        let producer = std::thread::spawn(move || {
            for i in 0..N {
                if let Some(rec) = slicer.process(&frame, i, false) {
                    if tx.send(rec).is_err() {
                        break;
                    }
                }
            }
        });

        let t0 = Instant::now();
        writer.run(&rx).unwrap();
        let dt = t0.elapsed().as_secs_f64();
        producer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let n_written = written.load(Ordering::Relaxed);
        let n_dropped = dropped.load(Ordering::Relaxed);
        let pps = n_written as f64 / dt;
        eprintln!(
            "full pipeline (slicer→channel→wal tmpfs, 512B): {:.0} pps ({:.2} Mpps), {} written / {} dropped in {:.2}s",
            pps, pps / 1e6, n_written, n_dropped, dt
        );
        // 全链路应明显高于 200k 压测点；否则瓶颈就在交付路径
        assert!(n_written > 0, "writer 未写入任何记录");
    }
}

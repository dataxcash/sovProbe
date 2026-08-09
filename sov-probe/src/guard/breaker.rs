use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Receiver;
use procfs::Current;

use crate::config::Config;

/// 双层熔断（高危盲区①修复）：
/// - 第一层：热路径队列深度，毫秒级原子降级（writer 侧检查 Receiver 水位）
/// - 第二层：后台 procfs 慢采样，评估宿主整体负载
#[derive(Clone)]
pub struct Breaker {
    pub degraded: Arc<AtomicBool>,
    pub dropped: Arc<AtomicU64>,
}

impl Breaker {
    pub fn new() -> Self {
        Self {
            degraded: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 当前是否降级。
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// 第一层热路径（writer 侧）：检查队列水位，超水位置 degraded。
    pub fn hot_path_check(&self, rx: &Receiver<crate::wal::header::WalRecord>, watermark: u8) {
        if let Some(capacity) = rx.capacity() {
            let fill = rx.len();
            let pct = (fill * 100) / capacity;
            if pct >= watermark as usize {
                self.degraded.store(true, Ordering::Release);
                return;
            }
            // 水位回落一半 → 恢复
            if pct < (watermark as usize) / 2 {
                self.degraded.store(false, Ordering::Release);
            }
        }
    }
}

impl Default for Breaker {
    fn default() -> Self {
        Self::new()
    }
}

/// 第二层：后台 procfs 慢采样线程。
pub fn run_background_sampler(
    cfg: Config,
    degraded: Arc<AtomicBool>,
    loop_interval: Duration,
) {
    std::thread::spawn(move || loop {
        // 进程自身 RSS 超限
        if let Ok(mem) = procfs::process::Process::myself().and_then(|p| p.statm()) {
            let rss_bytes = mem.resident as u64 * 4096;
            if rss_bytes > cfg.ram_limit_mb * 1024 * 1024 {
                degraded.store(true, Ordering::Release);
            }
        }
        // 宿主整体负载
        if let Ok(load) = procfs::LoadAverage::current() {
            let one_min = load.one;
            let cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1) as f32;
            let pct = (one_min / cores * 100.0) as u8;
            if pct > cfg.host_cpu_limit_pct {
                degraded.store(true, Ordering::Release);
            }
        }
        // 未触发 → 由热路径水位决定恢复，慢采样不做恢复（避免抖动）
        std::thread::sleep(loop_interval);
    });
}

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
///
/// TC-3 实测缺陷修复：原实现只置 degraded 永不恢复（注释称"由热路径水位决定恢复"，
/// 但 RSS/负载触发的降级热路径无法感知）。洪泛期分配器高水位滞留使 RSS 长期超限 →
/// 探针永久降级（written 冻结、不随负载回落恢复）。
/// 方案：
/// - 触发：RSS 超限 或 负载超限 → degraded=true；
/// - 恢复：RSS 与负载**双双**回落到触发阈值 ~80%（滞回带）以下 → degraded=false，
///   避免临界抖动；
/// - 每周期 `malloc_trim(0)` 归还分配器滞留堆，使 RSS 反映真实工作集而非高水位。
pub fn run_background_sampler(
    cfg: Config,
    degraded: Arc<AtomicBool>,
    loop_interval: Duration,
) {
    std::thread::spawn(move || loop {
        // 归还分配器滞留堆：洪泛期大量 4KB 级 Vec 分配后，arena 高水位滞留会让
        // RSS 长期虚高 → ram_limit 误触发且无法恢复
        #[cfg(target_os = "linux")]
        unsafe {
            libc::malloc_trim(0);
        }

        let mut should_recover = true;

        // 进程自身 RSS
        if let Ok(mem) = procfs::process::Process::myself().and_then(|p| p.statm()) {
            let rss_bytes = mem.resident * 4096;
            let limit = cfg.ram_limit_mb * 1024 * 1024;
            if rss_bytes > limit {
                degraded.store(true, Ordering::Release);
                should_recover = false;
            } else if rss_bytes > limit * 8 / 10 {
                // 滞回带内：保持现状，避免临界抖动
                should_recover = false;
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
                should_recover = false;
            } else if pct > cfg.host_cpu_limit_pct * 8 / 10 {
                should_recover = false;
            }
        }

        // RSS 与负载双双回落到阈值以下 → 自动恢复（滞回防抖）
        if should_recover {
            degraded.store(false, Ordering::Release);
        }

        std::thread::sleep(loop_interval);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::header::{encode_ip, WalRecord};
    use crossbeam_channel::{bounded, unbounded};

    fn sample_record() -> WalRecord {
        WalRecord {
            timestamp_ns: 1,
            flags: 0,
            tcp_flags: 0x02,
            src_ip: encode_ip(Some([192, 168, 1, 10]), None).0,
            dst_ip: encode_ip(Some([10, 0, 0, 1]), None).0,
            src_port: 12345,
            dst_port: 443,
            proto: 6,
            orig_payload_len: 10,
            payload: b"0123456789".to_vec(),
        }
    }

    fn fill(tx: &crossbeam_channel::Sender<WalRecord>, n: usize) {
        for _ in 0..n {
            let _ = tx.send(sample_record());
        }
    }

    fn drain(rx: &Receiver<WalRecord>, n: usize) {
        for _ in 0..n {
            let _ = rx.try_recv();
        }
    }

    #[test]
    fn fresh_breaker_not_degraded() {
        let b = Breaker::new();
        assert!(!b.is_degraded());
        assert_eq!(b.dropped.load(Ordering::Relaxed), 0);
    }

    /// 队列水位 ≥ watermark → 置 degraded。
    #[test]
    fn watermark_triggers_degradation() {
        let (tx, rx) = bounded::<WalRecord>(100);
        fill(&tx, 80);
        let b = Breaker::new();
        b.hot_path_check(&rx, 80);
        assert!(b.is_degraded(), "80% ≥ 80% 水位应降级");
    }

    /// 略低于水位（79%）→ 不降级（整数百分比计算）。
    #[test]
    fn just_below_watermark_keeps_healthy() {
        let (tx, rx) = bounded::<WalRecord>(100);
        fill(&tx, 79);
        let b = Breaker::new();
        b.hot_path_check(&rx, 80);
        assert!(!b.is_degraded());
    }

    /// 水位回落到一半以下 → 自动恢复。
    #[test]
    fn below_half_recovers() {
        let (tx, rx) = bounded::<WalRecord>(100);
        fill(&tx, 80);
        let b = Breaker::new();
        b.hot_path_check(&rx, 80);
        assert!(b.is_degraded());
        drain(&rx, 50); // 剩 30%，< watermark/2=40%
        b.hot_path_check(&rx, 80);
        assert!(!b.is_degraded(), "30% < 40% 应恢复");
    }

    /// 滞回带内（watermark/2 ~ watermark）→ 保持现状，防临界抖动。
    #[test]
    fn hysteresis_zone_holds_state() {
        // 健康态 60%：不高也不低 → 保持 false
        let (tx, rx) = bounded::<WalRecord>(100);
        fill(&tx, 60);
        let b = Breaker::new();
        b.hot_path_check(&rx, 80);
        assert!(!b.is_degraded());

        // 降级态 60%：未跌破一半 → 保持 true
        let (tx2, rx2) = bounded::<WalRecord>(100);
        fill(&tx2, 80);
        b.hot_path_check(&rx2, 80);
        assert!(b.is_degraded());
        drain(&rx2, 20); // 剩 60%
        b.hot_path_check(&rx2, 80);
        assert!(b.is_degraded(), "60% 在滞回带内应保持降级");
    }

    /// 无界通道 capacity()=None → 水位检查为 no-op。
    #[test]
    fn unbounded_channel_noop() {
        let (tx, rx) = unbounded::<WalRecord>();
        let b = Breaker::new();
        fill(&tx, 10_000);
        b.hot_path_check(&rx, 80);
        assert!(!b.is_degraded());
    }
}

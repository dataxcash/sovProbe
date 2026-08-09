use std::convert::TryFrom;

use aya::maps::ring_buf::RingBuf;
use aya::maps::HashMap;
use aya::programs::SchedClassifier;
use aya::programs::TcAttachType;
use aya::{include_bytes_aligned, Ebpf};
use crossbeam_channel::Sender;
use tracing::info;

use crate::config::Config;
use crate::guard::breaker::Breaker;

/// eBPF 加载 + 挂载。返回持有 bpf 的句柄，供后续 ringbuf 消费。
pub struct Capture {
    bpf: Ebpf,
}

impl Capture {
    pub fn load_and_attach(cfg: &Config) -> anyhow::Result<Self> {
        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpf/debug/capture.bpf.o"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpf/release/capture.bpf.o"
        ))?;

        // 写入端口白名单（类型化 HashMap）
        let mut port_filter: HashMap<_, u16, u8> = bpf
            .map_mut("port_filter_map")
            .ok_or_else(|| anyhow::anyhow!("port_filter_map 不存在"))?
            .try_into()?;
        for port in &cfg.capture_ports {
            port_filter.insert(port, &1u8, 0)?;
        }
        info!(
            "port_filter_map 已加载 {} 个端口",
            cfg.capture_ports.len()
        );

        // 加载 classifier 到各接口
        for iface in &cfg.interfaces {
            let program: &mut SchedClassifier = bpf
                .program_mut("sovprobe_classify")
                .ok_or_else(|| anyhow::anyhow!("sovprobe_classify 程序不存在"))?
                .try_into()?;
            program.load()?;
            program.attach(iface, TcAttachType::Egress)?;
            program.attach(iface, TcAttachType::Ingress)?;
            info!("eBPF 已挂载 {iface} egress+ingress");
        }

        Ok(Self { bpf })
    }

    /// 阻塞消费 RingBuffer：Slicer 解析 → crossbeam 队列。
    /// 热路径熔断：队列深度超水位时直接丢弃新帧（Drop-Tail，Fail-Open）。
    /// bpf 在此函数生命周期内保持存活（borrow 约束）。
    pub fn consume(
        &mut self,
        tx: Sender<crate::wal::header::WalRecord>,
        slice_bytes: usize,
        breaker: &Breaker,
    ) -> anyhow::Result<()> {
        let mut ring: RingBuf<_> = RingBuf::try_from(
            self.bpf
                .map_mut("events")
                .ok_or_else(|| anyhow::anyhow!("events map 不存在"))?,
        )?;
        let slicer = crate::parse::slicer::Slicer::new(slice_bytes);
        while let Some(item) = ring.next() {
            // 热路径熔断检查：degraded 时丢弃，不进入解析/WAL
            if breaker.is_degraded() {
                breaker.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
            let ts_ns: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .try_into()
                .unwrap_or(0);
            if let Some(rec) = slicer.process(item.as_ref(), ts_ns, breaker.is_degraded()) {
                if tx.send(rec).is_err() {
                    break; // 下游关闭
                }
            }
        }
        info!("ringbuf 消费结束");
        Ok(())
    }
}

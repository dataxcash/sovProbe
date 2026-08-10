use std::sync::atomic::Ordering;
use std::time::Duration;

use clap::Parser;
use crossbeam_channel::bounded;
use sov_probe::capture;
use sov_probe::config::Config;
use sov_probe::guard;
use sov_probe::metrics::Metrics;
use sov_probe::wal;
use tracing::{error, info, warn};

/// 铁幕·带外零信任主权平台 - sovProbe 零拷贝网络探针
#[derive(Parser, Debug)]
#[command(name = "sovprobe", version, about)]
struct Cli {
    /// 抓包接口，逗号分隔
    #[arg(long)]
    interface: String,
    /// 内核态端口白名单，逗号分隔（空=全量）
    #[arg(long, value_delimiter = ',')]
    capture_ports: Option<Vec<u16>>,
    /// Payload 裁切长度
    #[arg(long)]
    slice_bytes: Option<usize>,
    /// WAL 单段大小
    #[arg(long)]
    segment_size: Option<u64>,
    /// 定时轮转间隔（秒）
    #[arg(long)]
    rotate_interval: Option<u64>,
    /// /dev/shm 输出目录
    #[arg(long)]
    shm_path: Option<String>,
    /// 配置 TOML 文件
    #[arg(long)]
    config: Option<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sovprobe=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let mut cfg = Config::load(cli.config.as_deref())?;

    // CLI 覆盖
    cfg.interfaces = cli.interface.split(',').map(|s| s.trim().to_string()).collect();
    if let Some(ports) = cli.capture_ports {
        cfg.capture_ports = ports;
    }
    if let Some(v) = cli.slice_bytes {
        cfg.slice_bytes = v;
    }
    if let Some(v) = cli.segment_size {
        cfg.segment_size = v;
    }
    if let Some(v) = cli.rotate_interval {
        cfg.rotate_interval_secs = v;
    }
    if let Some(v) = cli.shm_path {
        cfg.shm_path = v;
    }
    cfg.validate()?;

    info!(
        "sovprobe 启动: 接口={:?}, 端口白名单={:?}, slice={}B",
        cfg.interfaces, cfg.capture_ports, cfg.slice_bytes
    );

    // 启动自检：shm 目录可写
    std::fs::create_dir_all(&cfg.shm_path)?;
    wal::rotate::check_writable(std::path::Path::new(&cfg.shm_path))?;
    info!("shm 目录可写: {}", cfg.shm_path);

    // 熔断器
    let breaker = guard::breaker::Breaker::new();
    guard::breaker::run_background_sampler(
        cfg.clone(),
        breaker.degraded.clone(),
        Duration::from_secs(cfg.sampler_interval_secs),
    );

    // 指标
    let metrics = Metrics::default();
    {
        let m = metrics.clone();
        let d = breaker.degraded.clone();
        let addr = cfg.metrics_addr.clone();
        std::thread::spawn(move || m.serve(&addr, d));
    }

    // 通道
    let (tx, rx) = bounded::<wal::header::WalRecord>(cfg.queue_capacity);
    let rx = std::sync::Arc::new(rx);

    // 共享计数
    let written_counter = metrics.written.clone();
    let dropped_counter = metrics.dropped.clone();

    // WAL 写入线程
    let mut writer = wal::writer::WalWriter::new(wal::writer::WriterParams {
        shm_path: cfg.shm_path.clone(),
        max_segments: cfg.max_segments,
        segment_size: cfg.segment_size,
        rotate_interval: Duration::from_secs(cfg.rotate_interval_secs),
        breaker: breaker.clone(),
        queue_watermark: cfg.queue_high_watermark,
        written_records: written_counter,
        dropped_records: dropped_counter,
    })?;
    let writer_rx = rx.clone();
    std::thread::spawn(move || {
        if let Err(e) = writer.run(&writer_rx) {
            error!("WAL writer 退出异常: {e}");
        }
    });

    // 捕获线程（RingBuffer → Slicer → crossbeam）
    let mut capture = capture::Capture::load_and_attach(&cfg)?;
    let capture_breaker = breaker.clone();
    std::thread::spawn(move || {
        let tx = tx;
        if let Err(e) = capture.consume(tx, cfg.slice_bytes, &capture_breaker) {
            error!("ringbuf 消费异常: {e}");
        }
    });

    // 主循环：心跳 + 熔断状态监控
    loop {
        std::thread::sleep(Duration::from_secs(10));
        if breaker.degraded.load(Ordering::Acquire) {
            warn!(
                "当前处于降级模式（Drop-Tail 中），已丢弃 {} 条, queue_fill={}/{}",
                metrics.dropped.load(Ordering::Relaxed),
                rx.len(),
                cfg.queue_capacity
            );
        } else {
            info!(
                "心跳: written={}, dropped={}, degraded_ev={}, queue_fill={}/{}",
                metrics.written.load(Ordering::Relaxed),
                metrics.dropped.load(Ordering::Relaxed),
                metrics.degraded.load(Ordering::Relaxed),
                rx.len(),
                cfg.queue_capacity
            );
        }
    }
}

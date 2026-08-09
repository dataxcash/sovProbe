use serde::Deserialize;

/// 探针全部可配置参数，CLI 与 TOML 双来源（CLI 优先级更高）。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 抓包接口，逗号分隔多接口
    pub interfaces: Vec<String>,
    /// 内核态端口白名单，空 = 全量抓取（Fallback）
    pub capture_ports: Vec<u16>,
    /// Payload 裁切长度
    pub slice_bytes: usize,
    /// WAL 单段大小
    pub segment_size: u64,
    /// 定时轮转间隔
    pub rotate_interval_secs: u64,
    /// 内存盘段数上限
    pub max_segments: usize,
    /// crossbeam 队列容量
    pub queue_capacity: usize,
    /// 队列水位触发百分比 (0-100)
    pub queue_high_watermark: u8,
    /// 进程 CPU% 熔断阈值
    pub cpu_limit_pct: f32,
    /// 进程 RAM 熔断阈值
    pub ram_limit_mb: u64,
    /// 宿主负载熔断阈值
    pub host_cpu_limit_pct: u8,
    /// shm 路径
    pub shm_path: String,
    /// 指标暴露地址
    pub metrics_addr: String,
    /// procfs 慢采样间隔
    pub sampler_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interfaces: vec![],
            capture_ports: vec![],
            slice_bytes: 4096,
            segment_size: 64 * 1024 * 1024,
            rotate_interval_secs: 5,
            max_segments: 8,
            queue_capacity: 100_000,
            queue_high_watermark: 80,
            cpu_limit_pct: 2.0,
            ram_limit_mb: 64,
            host_cpu_limit_pct: 85,
            shm_path: "/dev/shm/sov-probe".to_string(),
            metrics_addr: "0.0.0.0:9101".to_string(),
            sampler_interval_secs: 1,
        }
    }
}

impl Config {
    /// 从 TOML 文件加载（可缺省），再由 CLI 覆盖。
    pub fn load(path: Option<&str>) -> anyhow::Result<Config> {
        let mut cfg = Config::default();
        if let Some(p) = path {
            let raw = std::fs::read_to_string(p)?;
            cfg = toml::from_str(&raw)?;
        }
        Ok(cfg)
    }

    /// 校验关键参数，非法直接报错，避免运行时踩雷。
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.interfaces.is_empty(), "至少需要一个接口 --interface");
        anyhow::ensure!(self.slice_bytes > 0 && self.slice_bytes <= 65536, "slice_bytes 非法");
        anyhow::ensure!(self.segment_size > 0, "segment_size 非法");
        anyhow::ensure!(self.max_segments >= 1, "max_segments >= 1");
        anyhow::ensure!(
            self.queue_high_watermark <= 100,
            "queue_high_watermark 应在 0-100"
        );
        Ok(())
    }
}

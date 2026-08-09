use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 极简文本指标（Prometheus 兼容），无外部依赖。
#[derive(Clone, Default)]
pub struct Metrics {
    pub captured: Arc<AtomicU64>,
    pub written: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
    pub degraded: Arc<AtomicU64>,
    pub slicer_dropped: Arc<AtomicU64>,
}

impl Metrics {
    pub fn render(&self, degraded_now: bool) -> String {
        format!(
            "# HELP sovprobe_captured_total 捕获帧数\n\
             # TYPE sovprobe_captured_total counter\n\
             sovprobe_captured_total {}\n\
             # TYPE sovprobe_written_total counter\n\
             sovprobe_written_total {}\n\
             # TYPE sovprobe_dropped_total counter\n\
             sovprobe_dropped_total {}\n\
             # TYPE sovprobe_degraded_total counter\n\
             sovprobe_degraded_total {}\n\
             # TYPE sovprobe_degraded_now gauge\n\
             sovprobe_degraded_now {}\n\
             # TYPE sovprobe_slicer_dropped_total counter\n\
             sovprobe_slicer_dropped_total {}\n",
            self.captured.load(Ordering::Relaxed),
            self.written.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            self.degraded.load(Ordering::Relaxed),
            degraded_now as u8,
            self.slicer_dropped.load(Ordering::Relaxed),
        )
    }

    /// 阻塞启动 HTTP 指标服务。
    pub fn serve(&self, addr: &str, degraded: Arc<std::sync::atomic::AtomicBool>) {
        let addr: SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("metrics 地址解析失败 {addr}: {e}");
                return;
            }
        };
        let listener = match std::net::TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("metrics 监听失败 {addr}: {e}");
                return;
            }
        };
        let metrics = self.clone();
        tracing::info!("metrics 已监听 {addr}");
        for stream in listener.incoming().flatten() {
            let metrics = metrics.clone();
            let degraded = degraded.clone();
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4096];
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                if stream.read(&mut buf).is_err() {
                    return;
                }
                let body = metrics.render(degraded.load(Ordering::Relaxed));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            });
        }
    }
}

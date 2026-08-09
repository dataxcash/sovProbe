# sovProbe — 铁幕·带外零信任主权平台网络探针

> 纯 Rust/eBPF 单二进制旁路网络探针：零拷贝抓包 → 智能裁切 → 内存 WAL，产出标准 64B 契约日志供 slimSync 无缝消费。

## 设计原则（第一硬红线）

1. **探针绝不阻塞生产**：Fail-Open，降级时 Drop-Tail 丢包，不反压内核。
2. **绝不拖垮宿主**：进程 CPU ≤ 2%、RAM ≤ 64MB（超限熔断）。
3. **RAMDisk 恒定 ≤ 512MB**：段号单向递增 + Unlink-Oldest（删除最旧段），物理文件恒为 max_segments 个，文件名全局唯一。

## 架构

```
[ 内核态 eBPF (tc) ]  Port-Filter 白名单 → RingBuffer
        ↓
[ 用户态 sovprobe ]   etherparse 解析 → Head-Slicer → 熔断
        ↓
/dev/shm/sov-probe/segment_*.wal   ← 64B Header 契约（标准本地管道）
        ↓  (fnotify)
[ slimSync ]  FastCDC 去重 → Zenoh → SovVault
```

## 快速开始

### 构建

```bash
cargo build --release   # 需要 clang + linux 头文件
```

产物：`target/release/sovprobe`（静态单二进制，<3MB）。

### 运行（需 root/CAP_NET_ADMIN）

```bash
sudo ./target/release/sovprobe \
  --interface eth0 \
  --capture-ports 80,443,8080,5432 \
  --shm-path /dev/shm/sov-probe
```

不带 `--capture-ports` 回退全量抓取。

### 配置

支持 TOML（`/etc/sovprobe.toml`），CLI 优先级更高：

```toml
interfaces = ["eth0"]
capture_ports = [80, 443, 8080, 5432]
slice_bytes = 4096
segment_size = 67108864          # 64MB
rotate_interval_secs = 5
max_segments = 8                 # RAMDisk 上限 512MB
queue_capacity = 100000
queue_high_watermark = 80
cpu_limit_pct = 2.0
ram_limit_mb = 64
host_cpu_limit_pct = 85
shm_path = "/dev/shm/sov-probe"
metrics_addr = "0.0.0.0:9101"
```

### 指标

`curl localhost:9101/metrics`：

```
sovprobe_captured_total
sovprobe_written_total
sovprobe_dropped_total
sovprobe_degraded_now
sovprobe_slicer_dropped_total
```

## WAL 64B 契约（v0.3）

```
Offset  Size  Field             Type
0       2     magic             u16 = 0x5350 ("SP")
2       1     version           u8 = 0x03
3       1     tcp_flags         u8 (FIN/SYN/RST/PSH/ACK/URG)
4       4     crc32             u32 (覆盖 header 除 crc32 字段全部 + payload)
8       8     timestamp_ns      u64 大端
16      16    src_ip            [u8;16] IPv4 高12B=0 低4B=大端
32      16    dst_ip            [u8;16] 同上
48      2     src_port          u16
50      2     dst_port          u16
52      1     proto             u8 (6=TCP,17=UDP)
53      3     reserved_pad      [u8;3] bit0=DEGRADED bit1=IS_IPV6
56      4     payload_len       u32 (incl_len，裁切后)
60      4     orig_payload_len  u32 (orig_len，线上原始)
───────────────────────────
64 字节 header + payload 原样
```

- **三重完整性校验**（Magic → Length → CRC32）：任一失败即丢弃脏尾，杜绝静默吃坏包。
- **TRUNCATED** 由 `orig_payload_len > payload_len` 推导；sov2pcap 据此映射 `orig_len > incl_len`，Wireshark 精准提示 snaplen truncated。
- 定长 64B 缓存行对齐；SovVault 端按 `pos += 64 + payload_len` 精确遍历。
- FastCDC 切块边界不对齐记录边界，**SovVault 必须做流式字节重组**（Stream Reassembly）。

## 降级与熔断（双层）

| 层 | 触发 | 延迟 |
|----|------|------|
| 热路径 | crossbeam 队列水位 > 80% | 毫秒级原子置位 |
| 慢采样 | 进程 RAM > 64MB / 宿主负载 > 85% | 1s procfs 轮询 |

degraded 期间新帧直接丢弃（Drop-Tail），绝不阻塞 ringbuf/内核。

## 与 slimSync 集成

slimSync 将 `/dev/shm/sov-probe` 作为 watch dir 监听即可（`.wal` 扩展名自动走 FastCDC 字节流轨，零改动）：

```toml
[watch]
dirs = ["/dev/shm/sov-probe"]
```

**段号单向递增**：segment_0000.wal, segment_0001.wal, ... 永不回写同名文件。超限时 sovProbe 直接 `remove_file` 删除最旧段（Unlink-Oldest），slimSync 比对文件名序号即可感知「旧段已抛弃」；新段是新 inode，触发 `IN_CREATE`，与「追加」语义无歧义。slimSync 崩溃/断网不影响探针采集；网络恢复后从 read_cursor 增量续读。

## WAL → PCAP 离线转码（sov2pcap）

出问题时直接转 pcap 扔进 Wireshark：

```bash
# 单个 WAL
sov2pcap -i /dev/shm/sov-probe/segment_0101.wal -o /tmp/dump.pcap
# 批量 + 端口过滤
sov2pcap -d /dev/shm/sov-probe/ -O /tmp/pcaps/ --filter-port 8080
```

从 64B Header 恢复五元组/时间戳，合成 Ethernet + IPv4/IPv6 + TCP/UDP 头输出标准 PCAP。**注意**：TCP seq/ack 为合成占位、协议头校验和置 0（Wireshark 自算），适用于 HTTP/API 请求语义分析；TCP 流重组/重传分析需 Header v0.3（补充 TCP flags/seq）后实现。

## 目录结构

```
src/
├── main.rs          CLI + 线程编排
├── lib.rs           公共库（wal/parse/guard/capture 供工具复用）
├── config.rs        配置（CLI + TOML）
├── capture/         eBPF 加载 + Port-Filter + RingBuffer
├── parse/slicer.rs  零拷贝解析 + 裁切
├── guard/breaker.rs 双层熔断
├── wal/             64B header + writer + Unlink-Oldest 轮转
├── bin/genwal.rs    WAL 生成测试工具
└── bin/sov2pcap.rs  WAL → PCAP 离线转码
bpf/capture.bpf.c    内核态端口白名单过滤
```

## 测试

```bash
cargo test            # header 契约、单调递增段号、Unlink-Oldest、残段重组
cargo run --release --bin genwal /tmp/sov-probe   # 生成测试 WAL
cargo run --release --bin sov2pcap -i /tmp/sov-probe/segment_0000.wal -o /tmp/a.pcap
```

## 验收目标

| 指标 | 目标 | 当前 |
|------|------|------|
| 二进制体积 | <10MB | 2.1MB |
| 常驻 RAM | <30MB | 待实测 |
| 进程 CPU | ≤2% | 熔断保障 |
| RAMDisk | ≤512MB | Unlink-Oldest 保障 |
| 吞吐 | ≥200k pps | 待实测 |

#!/usr/bin/env bash
# VM-1（探针 + 传输）测试驱动 — 11 段复验 + TC-2 断连 + TC-3 高 pps
# 用法：sudo bash vm1_run.sh <VM2_IP>
# 前置：sovprobe 已以 /etc/sovprobe.toml 运行；本机为 2C4G 测试节点，禁止本机发包。
set -uo pipefail
VM2_IP=${1:?用法: vm1_run.sh <VM2_IP>}
SLIMSYNC_BIN=${SLIMSYNC_BIN:-/usr/local/bin/slimsync}
CONF=/etc/slimsync.toml
SEED_DIR=/dev/shm/sov-probe
LOG=/var/log/slimsync-vm1.log
HERE="$(cd "$(dirname "$0")" && pwd)"

# 生成 slimsync 配置（connect 指向 VM-2）
mkdir -p /etc/slimsync
[ -f /etc/slimsync/key.bin ] || head -c 32 /dev/urandom > /etc/slimsync/key.bin
[ -f /etc/slimsync/salt.bin ] || head -c 16 /dev/urandom > /etc/slimsync/salt.bin
cat > "$CONF" <<EOF
[general]
log_level = "info"
dev_id = 1
[watch]
dirs = ["$SEED_DIR"]
debounce_ms = 200
exclude = []
[crypto]
key_file = "/etc/slimsync/key.bin"
salt_file = "/etc/slimsync/salt.bin"
[storage]
db_path = "/var/lib/slimsync/slimsync.db"
[zenoh]
mode = "client"
connect = ["tcp/$VM2_IP:7447"]
timeout_ms = 5000
EOF
chmod 600 /etc/slimsync/key.bin

say() { echo; echo "########## $* ##########"; }

# ── 第二步：11 段真实流量复验（冷启动走段状态机）──
say "STEP-2 11 段复验：重启 slimSync 触发冷启动段状态机"
pkill -x slimsync 2>/dev/null; sleep 1
nohup "$SLIMSYNC_BIN" --config "$CONF" >> "$LOG" 2>&1 &
sleep 6
grep -oE "segment_plans=[0-9]+" "$LOG" | tail -1
say "STEP-2 对账在 VM-2 侧执行（md5 逐段 / gaps=0 / sealed=11）"

# ── TC-2 断连（配合 VM-2 侧 iptables DROP 7447）──
say "TC-2 断连 30s：RSS 采样（断言 ≤32MB）"
for i in $(seq 1 30); do
  rss=$(ps -o rss= -C slimsync 2>/dev/null | tr -d ' ' || echo 0)
  echo "t=${i}s rss_kb=${rss:-0}"
  [ "${rss:-0}" -gt 32768 ] && echo "!! RSS 超 32MB 阈值" 
  sleep 1
done

# ── TC-3 高 pps（发包器在 VM-2；本机只观察）──
say "TC-3 压测观察：sovprobe metrics 5 次采样"
for i in 1 2 3 4 5; do
  curl -sf http://127.0.0.1:9101/metrics 2>/dev/null | grep -E "sovprobe_(captured|written|dropped)_total|sovprobe_degraded_now" || echo "metrics 不可用"
  sleep 5
done
say "VM-1 侧完成；对账在 VM-2。"

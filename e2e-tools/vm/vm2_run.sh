#!/usr/bin/env bash
# VM-2（注入 + 接收）测试驱动 — 11 段复验 + TC-2 断连 + TC-3 200k pps
# 用法：bash vm2_run.sh <VM1_IP> [--tc3-pktgen|--tc3-netem]
# 前置：sub_save_test/genwal_distinct/sov2pcap 已部署到 /usr/local/bin；wrk/iperf3/tshark 已装。
set -uo pipefail
VM1_IP=${1:?用法: vm2_run.sh <VM1_IP> [--tc3-mode]}
TC3_MODE=${2:---tc3-netem}
KEY_HEX=${KEY_HEX:-}
OUT=/data/reassembled
LEDGER=/data/reassembled/ledger
HERE="$(cd "$(dirname "$0")" && pwd)"
NIC=${VM2_NIC:-eth0}

[ -n "$KEY_HEX" ] || { echo "需设置 KEY_HEX 与 VM-1 /etc/slimsync/key.bin 一致（32B hex）"; exit 1; }

say() { echo; echo "########## $* ##########"; }
finish() { pkill -INT -x sub_save_test 2>/dev/null; pkill -INT -x slimsync 2>/dev/null; }
trap finish EXIT

# 启动接收端
say "启动 sub_save_test (listen 7447)"
mkdir -p "$OUT"
nohup /usr/local/bin/sub_save_test --listen tcp/0.0.0.0:7447 --out "$OUT" --key-hex "$KEY_HEX" > /var/log/sub_save_test.log 2>&1 &
SUB_PID=$!
sleep 3

# ── 第二步：11 段复验对账 ──
say "STEP-2 11 段复验对账（等待 VM-1 冷启动完成）"
sleep 20
OK=0; TOT=0
for f in "$OUT"/segment_*.wal; do
  [ -e "$f" ] || continue
  TOT=$((TOT+1))
done
echo "重组段数: $TOT（期望 11）"
grep -E "STAT|SEAL" /var/log/sub_save_test.log | tail -3
grep -q "gaps=[1-9]" /var/log/sub_save_test.log && echo "!! gaps>0 存在缺失" || echo "gaps=0 OK"
grep -q "cache_miss=[1-9]" /var/log/sub_save_test.log && echo "!! cache_miss>0" || echo "cache_miss=0 OK"

# ── TC-1：wrk 跨网注入 ──
say "TC-1 wrk 跨网注入 10k 请求"
wrk -t4 -c100 -d60s -s "$HERE/inject.lua" "http://$VM1_IP:8080/api/orders" 2>&1 | tail -8

# ── TC-2：断连 30s ──
say "TC-2 DROP 7447 入站 30s（配合 VM-1 观察 RSS）"
iptables -A INPUT -p tcp --dport 7447 -j DROP
sleep 30
iptables -D INPUT -p tcp --dport 7447 -j DROP
sleep 10
say "TC-2 恢复后 STAT"
grep -E "STAT|SEAL" /var/log/sub_save_test.log | tail -3

# ── TC-3：200k pps 注入 ──
say "TC-3 高 pps 注入（$TC3_MODE）"
case "$TC3_MODE" in
  --tc3-pktgen)
    # 轻量方案：内核 /proc/net/pktgen（零安装，替代 DPDK，见 docs §9.7）。
    # pktgen 接管 $NIC 会短暂断连 VM-2 的 SSH；脚本 count*delay 有界自终止后自动释放。
    sudo modprobe pktgen
    # TC-3a：非目标端口 → Port-Filter 放行断言
    sudo bash "$HERE/pktgen_tc3.sh" 5001 12000000 5000
    # TC-3b：目标端口 8080 → Drop-Tail 降级 + 负载回落后自动恢复断言
    sudo bash "$HERE/pktgen_tc3.sh" 8080 12000000 5000
    ;;
  --tc3-netem)
    # 降级方案：多实例 sockperf 聚合 + tc 突发（无 DPDK 时）
    tc qdisc add dev "$NIC" root netem rate 1gbit 2>/dev/null || true
    for i in 1 2 3 4; do
      sockperf under-load --ip "$VM1_IP" --tcp --duration 60 --pps 50000 >/dev/null 2>&1 &
    done
    sleep 65
    tc qdisc del dev "$NIC" root 2>/dev/null || true
    ;;
esac
sleep 10
say "TC-3 结束后 STAT"
grep -E "STAT|SEAL" /var/log/sub_save_test.log | tail -3
say "落盘产物"
ls -la "$OUT" | tail -15

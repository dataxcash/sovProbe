#!/bin/bash
# VM-2 TC-3 内核 pktgen 压测（有界自终止）— 替代 DPDK
#
# 用法: sudo bash pktgen_tc3.sh <port> <count> <delay_ns>
#   delay 5000ns = 200k pps; count 12000000 * 5us = 60s
# 说明: pktgen 会接管 $NIC 的发送路径，短暂断连该网卡上的 SSH/业务；
#       脚本按 count*delay 预算 sleep 后自动释放网卡，无需人工干预。
#
# 环境变量可覆盖:
#   VM2_NIC=  默认 enp0s4（注入网卡）
#   DST_IP=   默认 192.168.100.10（目标 VM-1）
#   DST_MAC=  默认 52:54:00:bb:00:0a（目标 VM-1 enp0s4 MAC）
set -u
PORT=${1:?用法: pktgen_tc3.sh <port> <count> <delay_ns>}
COUNT=${2:?count}
DELAY=${3:?delay_ns}
NIC=${VM2_NIC:-enp0s4}
DST_IP=${DST_IP:-192.168.100.10}
DST_MAC=${DST_MAC:-52:54:00:bb:00:0a}
P=/proc/net/pktgen/$NIC
echo "stop" > /proc/net/pktgen/pgctrl 2>/dev/null
echo "rem_device_all" > /proc/net/pktgen/kpktgend_0 2>/dev/null
echo "add_device $NIC" > /proc/net/pktgen/kpktgend_0
echo "dst $DST_IP" > $P
echo "dst_mac $DST_MAC" > $P
echo "pkt_size 128" > $P
echo "delay $DELAY" > $P
echo "count $COUNT" > $P
echo "udp_src_min 40000" > $P
echo "udp_src_max 40000" > $P
echo "udp_dst_min $PORT" > $P
echo "udp_dst_max $PORT" > $P
echo "start" > /proc/net/pktgen/pgctrl
echo "$(date +%H:%M:%S) START port=$PORT count=$COUNT delay=$DELAY" >> /tmp/pktgen_tc3.log
# 等待 count 耗尽（约 count*delay_ns 秒），再缓冲 5s 确保链路恢复
sleep $(( (COUNT * DELAY) / 1000000000 + 5 ))
echo "rem_device_all" > /proc/net/pktgen/kpktgend_0 2>/dev/null
echo "stop" > /proc/net/pktgen/pgctrl 2>/dev/null
echo "$(date +%H:%M:%S) DONE port=$PORT" >> /tmp/pktgen_tc3.log

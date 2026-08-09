#!/usr/bin/env bash
# 生成 11 段受控数据（第二步复验种子），可选拷到 VM-1 watch 目录
# 用法: bash seed_11seg.sh <输出目录> [VM1_HOST]  # VM1_HOST 提供则 scp 过去
set -uo pipefail
OUT=${1:?用法: seed_11seg.sh <输出目录> [VM1_HOST]}
VM1=${2:-}
rm -rf "$OUT"; mkdir -p "$OUT"
for s in $(seq 0 10); do
  /usr/local/bin/genwal_distinct "$OUT" "$s" >/dev/null
done
echo "生成 11 段于 $OUT："
ls -la "$OUT" | grep segment_
if [ -n "$VM1" ]; then
  scp "$OUT"/segment_*.wal "root@$VM1:/dev/shm/sov-probe/" && echo "已拷到 $VM1"
fi

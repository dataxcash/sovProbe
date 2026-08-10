# sovProbe — Out-of-Band Zero-Trust Network Probe (Rust + eBPF)

> A pure-Rust/eBPF **single-binary out-of-band packet probe**: zero-copy capture → smart head-slicing → in-memory WAL.
> Emits a standard 64-byte contract log, consumed seamlessly by [slimSync](https://github.com/dataxcash/slimRAG) for
> FastCDC-dedup, ChaCha20-encrypted, Zenoh transport.

## Why out-of-band

The probe attaches an eBPF **tc hook (ingress + egress)** and never sits in the data path. Production traffic flows
unchanged; the probe only *observes*. Port-whitelisted packets are copied into a 1 MB kernel ring buffer; every other
packet passes through untouched. **Zero blocking, zero inline risk, zero SPOF anxiety.**

## Key features

- **Port-Filter whitelist** — only configured ports (e.g. `8080`) are captured; non-target packets pass through.
- **Head-Slicer** — keeps HTTP headers / JSON roots, truncates large bodies (original on-wire length preserved).
- **64-byte WAL header contract** — `Magic → Length → CRC32` triple validation rejects dirty tails; no silent bad data.
- **Dual-layer circuit breaker** — hot-path queue watermark (>80%) + slow-path procfs sampling
  (process RSS > 64 MB / host load > 85%) → **Drop-Tail fail-open** with automatic recovery.
- **Unlink-Oldest rotation** — monotonic segment numbers, RAMDisk bounded ≤ 512 MB, files globally unique.
- **Tiny footprint** — ~1.7k lines (1,535 Rust + eBPF C), **2.1 MB static single binary**, idle 36 MB RAM / <0.5% CPU.

## Architecture

```
[ kernel eBPF (tc) ]    Port-Filter whitelist → RingBuffer (1 MB)
        ↓
[ userspace sovprobe ]  etherparse parse → Head-Slicer → circuit breaker
        ↓
/dev/shm/sov-probe/segment_*.wal   ← 64 B header contract (standard local pipe)
        ↓  (inotify/fanotify)
[ slimSync ]  FastCDC → ChaCha20 → Zenoh → SovVault
```

## Repository layout

```
sov-probe/    the probe: CLI + capture (eBPF) + parse/slicer + guard/breaker + wal (64 B header / writer / rotation)
e2e-tools/    E2E verification harness: sub_save_test (receiver/reassembler), genwal, sov2pcap, VM pktgen driver
```

## Quick start

Requires a Linux kernel with BTF (5.8+), `clang`, and Linux headers.

```bash
cd sov-probe
cargo build --release        # static single binary: target/release/sovprobe (2.1 MB)

sudo ./target/release/sovprobe \
  --interface eth0 \
  --capture-ports 8080 \
  --shm-path /dev/shm/sov-probe
```

TOML config (`/etc/sovprobe.toml`) mirrors the CLI flags; metrics on `:9101/metrics`
(`sovprobe_written_total`, `sovprobe_dropped_total`, `sovprobe_degraded_now`, …).

See [sov-probe/README.md](./sov-probe/README.md) for the full 64-byte WAL contract, configuration, and the
WAL→PCAP offline decoder (`sov2pcap`).

## Verified on real VMs (data-driven)

Full-chain E2E on real halo VMs (VM-1 = sovProbe + slimSync, VM-2 = receiver + generator, bridged):

| Scenario | Result |
|----------|--------|
| 11-segment WAL re-verification | **md5 11/11 byte-identical** |
| Real traffic @ 1885 req/s | 1.4 GB / 578 k chunks reassembled, **md5 6/6** |
| TC-3a Port-Filter pass-through | 12 M non-target packets @ 200 k pps → **0 captured** |
| TC-3b Drop-Tail degradation | 12 M target packets @ 200 k pps → **3.54 M dropped**, fail-open |
| TC-3b auto-recovery | degraded flag clears, writes resume, RSS 350 MB → 36 MB |
| Unit tests | **9 tests, 0.03 s** (WAL contract, rotation, slicing) |

Injection uses the in-kernel `/proc/net/pktgen` (no DPDK); assertions via `:9101/metrics` + on-disk md5.

## License

MIT — the open-source core. The IronCurtain hardware trust layer (KeyD) and enterprise control-plane are proprietary
and not included here.

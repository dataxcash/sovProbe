#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 内核态极简 Port-Filter（致命缺陷②修复）：
// 读 L4 端口 → 查白名单 Map → 命中推入 RingBuffer，未命中 TC_ACT_OK 放行。
// 不做任何 payload 解析，零分配，审计面极小。

#define MAX_COPY 4608 // 足够 64B header + 4KB 裁切 + L2/L3/L4 头

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} port_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ringbuf
} events SEC(".maps");

SEC("classifier")
int sovprobe_classify(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) > data_end) {
        return TC_ACT_OK;
    }

    __u16 proto = bpf_ntohs(eth->h_proto);
    __u16 src_port = 0, dst_port = 0;
    __u32 l4_off = 0;

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end) {
            return TC_ACT_OK;
        }
        l4_off = sizeof(*eth) + (ip->ihl * 4);
        // TCP/UDP only
        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        if ((void *)ip6 + sizeof(*ip6) > data_end) {
            return TC_ACT_OK;
        }
        l4_off = sizeof(*eth) + sizeof(struct ipv6hdr);
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
    } else {
        return TC_ACT_OK; // 非 IP 直接放行
    }

    struct udphdr *udp = (void *)data + l4_off;
    if ((void *)udp + sizeof(*udp) > data_end) {
        return TC_ACT_OK;
    }
    // 端口布局 TCP/UDP 头一致
    src_port = bpf_ntohs(udp->source);
    dst_port = bpf_ntohs(udp->dest);

    // 白名单过滤：命中 dst 或 src 才入队；空 map（未配置）→ 全量
    __u8 *hit = bpf_map_lookup_elem(&port_filter_map, &dst_port);
    if (!hit) {
        hit = bpf_map_lookup_elem(&port_filter_map, &src_port);
    }
    if (!hit) {
        return TC_ACT_OK;
    }

    void *buf = bpf_ringbuf_reserve(&events, MAX_COPY, 0);
    if (!buf) {
        return TC_ACT_OK; // ringbuf 满 → 静默丢包，fail-open
    }

    __u32 copy_len = skb->len < MAX_COPY ? skb->len : MAX_COPY;
    if (copy_len == 0) {
        bpf_ringbuf_discard(buf, 0);
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, 0, buf, copy_len) == 0) {
        bpf_ringbuf_submit(buf, 0);
    } else {
        bpf_ringbuf_discard(buf, 0);
    }
    return TC_ACT_OK; // 旁路探针：放行，绝不阻塞
}

char _license[] SEC("license") = "GPL";

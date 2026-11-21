/*
 * WirePulse Companion eBPF / XDP High-Speed Telemetry Program
 *
 * Demonstrates kernel-space L2/L3/L4 packet counting & SYN flood early-warning
 * at the XDP driver ingress hook (before sk_buff allocation in Linux kernel).
 *
 * Build on Linux with clang + libbpf headers:
 *   clang -O2 -g -target bpf -c xdp_packet_stats.bpf.c -o xdp_packet_stats.bpf.o
 */
#ifdef __BPF__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum wp_proto_bucket {
    BUCKET_TOTAL = 0,
    BUCKET_IPV4  = 1,
    BUCKET_IPV6  = 2,
    BUCKET_ARP   = 3,
    BUCKET_TCP   = 4,
    BUCKET_UDP   = 5,
    BUCKET_ICMP  = 6,
    BUCKET_SYN   = 7,
    BUCKET_MAX   = 8,
};

struct wp_proto_counter {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, BUCKET_MAX);
    __type(key, __u32);
    __type(value, struct wp_proto_counter);
} wp_xdp_stats SEC(".maps");

static __always_inline void bump_counter(__u32 key, __u64 pkt_len) {
    struct wp_proto_counter *cnt = bpf_map_lookup_elem(&wp_xdp_stats, &key);
    if (cnt) {
        cnt->packets += 1;
        cnt->bytes += pkt_len;
    }
}

SEC("xdp")
int wirepulse_xdp_monitor(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = (__u64)(data_end - data);

    bump_counter(BUCKET_TOTAL, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto == ETH_P_ARP) {
        bump_counter(BUCKET_ARP, pkt_len);
        return XDP_PASS;
    }

    if (h_proto == ETH_P_IP) {
        bump_counter(BUCKET_IPV4, pkt_len);
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }
        __u32 ihl_bytes = iph->ihl * 4;
        if (ihl_bytes < sizeof(*iph) || (void *)iph + ihl_bytes > data_end) {
            return XDP_PASS;
        }
        if (iph->protocol == IPPROTO_TCP) {
            bump_counter(BUCKET_TCP, pkt_len);
            struct tcphdr *tcph = (void *)iph + ihl_bytes;
            if ((void *)(tcph + 1) <= data_end && tcph->syn && !tcph->ack) {
                bump_counter(BUCKET_SYN, pkt_len);
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            bump_counter(BUCKET_UDP, pkt_len);
        } else if (iph->protocol == IPPROTO_ICMP) {
            bump_counter(BUCKET_ICMP, pkt_len);
        }
    } else if (h_proto == ETH_P_IPV6) {
        bump_counter(BUCKET_IPV6, pkt_len);
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) <= data_end) {
            if (ip6h->nexthdr == IPPROTO_TCP)      bump_counter(BUCKET_TCP, pkt_len);
            else if (ip6h->nexthdr == IPPROTO_UDP) bump_counter(BUCKET_UDP, pkt_len);
            else if (ip6h->nexthdr == IPPROTO_ICMPV6) bump_counter(BUCKET_ICMP, pkt_len);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
#endif

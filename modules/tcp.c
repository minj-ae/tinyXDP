#include <errno.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <linux/in.h>
#include <sys/socket.h>


#define MAX_MAP_ENTRIES 131072

#define IP_NETWORK 0x258B8180  // 37.139.129.0/24

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80


#define MAX_SYN_RATE_LIMIT 3
#define MAX_SYNACK_RATE_LIMIT 20
#define MAX_ACK_RATE_LIMIT 2000
#define MAX_RST_RATE_LIMIT 1
#define MAX_FIN_RATE_LIMIT 1

#define RATE_LIMIT_RESET_INTERVAL_NS 1000000000 // 1s

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} syn_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} sack_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} ack_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} rst_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} fin_flood_map SEC(".maps");

// Helper function to handle rate limiting
static __always_inline int rate_limit(__u32 ip, __u16 flags, __u64 max_rate_limit, void *map) {
    struct {
        __u64 count;
        __u64 last_reset;
    } *now;

    now = bpf_map_lookup_elem(map, &ip);
    if (!now)
        return XDP_DROP;

    __u64 current_time = bpf_ktime_get_ns();
    if (current_time - now->last_reset >= RATE_LIMIT_RESET_INTERVAL_NS) {
        now->count = 0;
        now->last_reset = current_time;
    }

    if (now->count >= max_rate_limit)
        return XDP_DROP;

    now->count++;

    return XDP_PASS;
}

SEC("xdp")
int tinyxdp_base(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 ether_proto = bpf_ntohs(eth->h_proto);
    void *l3hdr = data + sizeof(struct ethhdr);

    if (ether_proto == ETH_P_ALL) {
        struct iphdr *ip = l3hdr;
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end)
                return XDP_DROP;

            __u32 src_ip = ip->saddr;
            __u16 flags = bpf_ntohs(tcp->th_flags);
            if ((src_ip & 0xFFFFFF00) == IP_NETWORK)
                return XDP_PASS;
            if (flags & TH_SYN) {
                if (!(flags & TH_ACK)) {
                    return rate_limit(src_ip, flags, MAX_SYN_RATE_LIMIT, &syn_flood_map);
                } else {
                    return rate_limit(src_ip, flags, MAX_SYNACK_RATE_LIMIT, &sack_flood_map);
                }
            } else if ((flags & TH_ACK) && !(flags & (TH_FIN | TH_RST | TH_PUSH))) {
                return rate_limit(src_ip, flags, MAX_ACK_RATE_LIMIT, &ack_flood_map);
            } else if (flags & TH_RST) {
                return rate_limit(src_ip, flags, MAX_RST_RATE_LIMIT, &rst_flood_map);
            } else if (flags & TH_FIN) {
                return rate_limit(src_ip, flags, MAX_FIN_RATE_LIMIT, &fin_flood_map);
            }
        }
    }
    return XDP_PASS; // Ensure all paths return a value
}

char _license[] SEC("license") = "GPL";

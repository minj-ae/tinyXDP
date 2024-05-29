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

#define MAX_SYN_RATE_LIMIT 1
#define MAX_SYNACK_RATE_LIMIT 60
#define MAX_ACK_RATE_LIMIT 3500
#define MAX_RST_RATE_LIMIT 1
#define MAX_FIN_RATE_LIMIT 1

#define RATE_LIMIT_RESET_INTERVAL_NS 1000000000 // 1s

enum conn_state {
    CONN_NEW,
    CONN_ESTABLISHED,
    CONN_RELATED,
    CONN_INVALID,
};

struct conn_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    enum conn_state state;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct conn_info);
} conntrack_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);
    __type(value, __u8);
} whitelist_map SEC(".maps");

static __always_inline int rate_limit(__u32 ip, __u16 flags, __u64 max_rate_limit, void *map) {
    struct {
        __u64 count;
        __u64 last_reset;
    } *now;

    __u64 key = ip;
    now = bpf_map_lookup_elem(map, &key);
    if (!now) {
        struct {
            __u64 count;
            __u64 last_reset;
        } new_entry = {0, bpf_ktime_get_ns()};
        bpf_map_update_elem(map, &key, &new_entry, BPF_ANY);
        now = bpf_map_lookup_elem(map, &key);
    }

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

static __always_inline enum conn_state get_conn_state(struct tcphdr *tcp) {
    if (tcp->syn && !tcp->ack)
        return CONN_NEW;
    if (tcp->syn && tcp->ack)
        return CONN_ESTABLISHED;
    if (tcp->fin || tcp->rst)
        return CONN_INVALID;
    if (tcp->ack)
        return CONN_ESTABLISHED;
    return CONN_INVALID;
}

static __always_inline int check_tcp_flags(__u16 flags) {
    if ((flags & (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG)) == 0)
        return XDP_DROP;
    if ((flags & (TH_FIN | TH_SYN)) == (TH_FIN | TH_SYN))
        return XDP_DROP;
    if ((flags & (TH_SYN | TH_RST)) == (TH_SYN | TH_RST))
        return XDP_DROP;
    if ((flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN))
        return XDP_DROP;
    if ((flags & (TH_FIN | TH_RST)) == (TH_FIN | TH_RST))
        return XDP_DROP;
    if ((flags & (TH_ACK | TH_FIN)) == TH_FIN)
        return XDP_DROP;
    if ((flags & (TH_ACK | TH_URG)) == TH_URG)
        return XDP_DROP;
    if ((flags & (TH_ACK | TH_FIN)) == TH_FIN)
        return XDP_DROP;
    if ((flags & (TH_ACK | TH_PUSH)) == TH_PUSH)
        return XDP_DROP;
    if ((flags & (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG)) == (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG))
        return XDP_DROP;
    if ((flags & (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG)) == 0)
        return XDP_DROP;
    if ((flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG))
        return XDP_DROP;
    if ((flags & (TH_SYN | TH_FIN | TH_PUSH | TH_URG)) == (TH_SYN | TH_FIN | TH_PUSH | TH_URG))
        return XDP_DROP;
    if ((flags & (TH_SYN | TH_RST | TH_ACK | TH_FIN | TH_URG)) == (TH_SYN | TH_RST | TH_ACK | TH_FIN | TH_URG))
        return XDP_DROP;

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

    if (ether_proto == ETH_P_IP) {
        struct iphdr *ip = l3hdr;
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end)
                return XDP_DROP;

            __u32 src_ip = ip->saddr;
            __u32 dst_ip = ip->daddr;
            __u16 src_port = bpf_ntohs(tcp->source);
            __u16 dst_port = bpf_ntohs(tcp->dest);
            __u64 conn_key = ((__u64)src_ip << 32) | dst_ip;

            __u8 *whitelist_val = bpf_map_lookup_elem(&whitelist_map, &src_ip);
            if (whitelist_val)
                return XDP_PASS;

            __u16 flags = ((__u16)tcp->fin) | ((__u16)tcp->syn << 1) | ((__u16)tcp->rst << 2) | ((__u16)tcp->psh << 3) |
                          ((__u16)tcp->ack << 4) | ((__u16)tcp->urg << 5);
            if (check_tcp_flags(flags) == XDP_DROP)
                return XDP_DROP;

            struct conn_info *conn = bpf_map_lookup_elem(&conntrack_map, &conn_key);
            enum conn_state state = get_conn_state(tcp);
            if (!conn) {
                struct conn_info new_conn = {
                    .src_ip = src_ip,
                    .dst_ip = dst_ip,
                    .src_port = src_port,
                    .dst_port = dst_port,
                    .state = state,
                    .last_seen = bpf_ktime_get_ns()
                };
                bpf_map_update_elem(&conntrack_map, &conn_key, &new_conn, BPF_ANY);
                conn = bpf_map_lookup_elem(&conntrack_map, &conn_key);
            } else {
                conn->last_seen = bpf_ktime_get_ns();
                conn->state = state;
            }

            if (conn) {
                switch (conn->state) {
                    case CONN_NEW:
                        return rate_limit(src_ip, tcp->th_flags, MAX_SYN_RATE_LIMIT, &syn_flood_map);
                    case CONN_ESTABLISHED:
                        return rate_limit(src_ip, tcp->th_flags, MAX_ACK_RATE_LIMIT, &ack_flood_map);
                    case CONN_RELATED:
                        return XDP_PASS;
                    case CONN_INVALID:
                    default:
                        return XDP_DROP;
                }
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

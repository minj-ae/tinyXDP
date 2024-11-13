#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAX_MAP_ENTRIES 131072

#define TIME_WINDOW_1S  1000000000ULL
#define TIME_WINDOW_5S  5000000000ULL
#define TIME_WINDOW_10S 10000000000ULL

#define LEARNING_PERIOD 300000000000ULL
#define UPDATE_INTERVAL 1000000000ULL
#define DEVIATION_WEIGHT 2
#define MAX_VIOLATION_THRESHOLD 5

#define STRICT_SYN_FLOOD_THRESHOLD 10
#define STRICT_PACKET_SIZE_MAX 1500
#define STRICT_MIN_PACKET_INTERVAL 1
#define BURST_DETECTION_WINDOW 100000
#define MAX_BURST_PACKETS 50
#define SUSPICIOUS_HEADER_CHECK 1
#define MAX_CONNECTIONS_PER_IP 15
#define CONNECTION_TIMEOUT 30000000000ULL

struct gre_hdr {
    __be16 flags;
    __be16 proto;
} __attribute__((packed));

#define GRE_CHECKSUM   0x8000
#define GRE_KEY        0x2000
#define GRE_SEQUENCE   0x1000
#define GRE_ROUTING    0x4000

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

enum conn_state {
    CONN_NEW,
    CONN_SYN_SENT,
    CONN_SYN_RECEIVED,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT_1,
    CONN_FIN_WAIT_2,
    CONN_TIME_WAIT,
    CONN_CLOSE,
    CONN_CLOSE_WAIT,
    CONN_LAST_ACK,
    CONN_RELATED,
    CONN_INVALID
};

struct conn_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    enum conn_state state;
    __u64 last_seen;
};

struct enhanced_traffic_stats {
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_update;
    __u64 baseline_rate;
    __u64 deviation;
    __u64 sudden_change;
    __u32 violation_count;
    __u64 last_baseline_update;
    
    __u32 syn_count;
    __u64 last_syn_reset;
    __u32 burst_count;
    __u64 last_burst_window;
    __u32 active_connections;
    __u64 last_packet_time;
    __u32 malformed_packet_count;
    __u32 fragment_count;
    __u32 sequence_error_count;
    __u32 blacklist_score;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct enhanced_traffic_stats);
} traffic_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct conn_info);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct {
        __u32 prefixlen;
        __u32 ip;
    });
    __type(value, __u32);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
} blacklist_map SEC(".maps");

static __always_inline int validate_packet(struct xdp_md *ctx, struct iphdr *ip, void *l4_header, __u8 protocol) {
    void *data_end = (void *)(long)ctx->data_end;
    
    if (ip->ihl < 5) return 0;
    if (ip->version != 4) return 0;
    
    __u32 ip_hlen = ip->ihl * 4;
    void *l4_start = (void *)ip + ip_hlen;
    if (l4_start > data_end)
        return 0;
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_header;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        if (tcp->doff < 5)
            return 0;
        void *tcp_end = (void *)tcp + (tcp->doff * 4);
        if (tcp_end > data_end)
            return 0;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end)
            return 0;
        if (bpf_ntohs(udp->len) < sizeof(struct udphdr))
            return 0;
    }
    
    return 1;
}

static __always_inline int check_tcp_flags(__u16 flags) {
    if ((flags & (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG)) == 0)
        return 0;
    if ((flags & (TH_FIN | TH_SYN)) == (TH_FIN | TH_SYN))
        return 0;
    if ((flags & (TH_SYN | TH_RST)) == (TH_SYN | TH_RST))
        return 0;
    if ((flags & (TH_SYN | TH_FIN)) == (TH_SYN | TH_FIN))
        return 0;
    if ((flags & (TH_FIN | TH_RST)) == (TH_FIN | TH_RST))
        return 0;
    return 1;
}

static __always_inline enum conn_state get_conn_state(enum conn_state current_state, __u16 flags) {
    switch (current_state) {
        case CONN_NEW:
            if (flags & TH_SYN)
                return CONN_SYN_SENT;
            break;
        case CONN_SYN_SENT:
            if ((flags & TH_SYN) && (flags & TH_ACK))
                return CONN_SYN_RECEIVED;
            break;
        case CONN_SYN_RECEIVED:
            if (flags & TH_ACK)
                return CONN_ESTABLISHED;
            break;
        case CONN_ESTABLISHED:
            if (flags & TH_FIN)
                return CONN_FIN_WAIT_1;
            break;
        default:
            return current_state;
    }
    return current_state;
}

static __always_inline int calculate_dynamic_threshold(struct enhanced_traffic_stats *stats, 
                                                     __u32 current_rate,
                                                     __u32 packet_size) {
    __u64 current_time = bpf_ktime_get_ns();
    
    if (stats->packet_count < 1000) {
        stats->baseline_rate = (stats->baseline_rate * stats->packet_count + current_rate) / 
                             (stats->packet_count + 1);
        stats->packet_count++;
        return 0;
    }

    if (current_time - stats->last_update >= UPDATE_INTERVAL) {
        if (current_time - stats->last_baseline_update >= TIME_WINDOW_10S) {
            stats->baseline_rate = (stats->baseline_rate * 7 + current_rate * 3) / 10;
            stats->last_baseline_update = current_time;
        }
        
        __u64 diff = current_rate > stats->baseline_rate ? 
                    current_rate - stats->baseline_rate : 
                    stats->baseline_rate - current_rate;
        
        stats->deviation = (stats->deviation * 7 + diff * 3) / 10;
        
        __u64 threshold = stats->baseline_rate + stats->deviation * DEVIATION_WEIGHT;
        if (current_rate > threshold) {
            stats->sudden_change++;
            if (stats->sudden_change >= 3) {
                stats->violation_count++;
                stats->sudden_change = 0;
            }
        } else {
            stats->sudden_change = 0;
            if (stats->violation_count > 0 && 
                current_time - stats->last_update >= TIME_WINDOW_5S) {
                stats->violation_count--;
            }
        }
        
        stats->last_update = current_time;
    }

    return stats->violation_count >= MAX_VIOLATION_THRESHOLD;
}

static __always_inline int enhanced_dynamic_threshold(struct enhanced_traffic_stats *stats, 
                                                    __u32 current_rate,
                                                    __u32 packet_size,
                                                    __u8 is_syn,
                                                    __u32 src_ip) {
    __u64 current_time = bpf_ktime_get_ns();
    
    if (stats->packet_count > 0) {
        __u64 packet_interval = current_time - stats->last_packet_time;
        if (packet_interval < STRICT_MIN_PACKET_INTERVAL) {
            stats->blacklist_score += 2;
            return 1;
        }
    }
    
    if (is_syn) {
        if (current_time - stats->last_syn_reset >= TIME_WINDOW_1S) {
            stats->syn_count = 0;
            stats->last_syn_reset = current_time;
        }
        stats->syn_count++;
        if (stats->syn_count > STRICT_SYN_FLOOD_THRESHOLD) {
            stats->blacklist_score += 5;
            return 1;
        }
    }
    
    if (current_time - stats->last_burst_window >= BURST_DETECTION_WINDOW) {
        stats->burst_count = 0;
        stats->last_burst_window = current_time;
    }
    stats->burst_count++;
    if (stats->burst_count > MAX_BURST_PACKETS) {
        stats->blacklist_score += 3;
        return 1;
    }
    
    if (packet_size > STRICT_PACKET_SIZE_MAX) {
        stats->blacklist_score += 2;
        return 1;
    }
    
    if (stats->active_connections >= MAX_CONNECTIONS_PER_IP) {
        stats->blacklist_score += 4;
        return 1;
    }
    
    if (stats->blacklist_score >= 10) {
        __u32 block_duration = 3600;
        bpf_map_update_elem(&blacklist_map, &src_ip, &block_duration, BPF_ANY);
        return 1;
    }
    
    if (calculate_dynamic_threshold(stats, current_rate, packet_size)) {
        stats->blacklist_score += 1;
        return 1;
    }
    
    if (current_time - stats->last_update >= TIME_WINDOW_5S && stats->blacklist_score > 0) {
        stats->blacklist_score--;
    }
    
    stats->last_packet_time = current_time;
    return 0;
}

static __always_inline int dynamic_rate_limit(__u32 ip, __u16 port, __u32 packet_size) {
    __u64 key = ((__u64)ip << 32) | port;
    struct enhanced_traffic_stats *stats = bpf_map_lookup_elem(&traffic_stats_map, &key);
    
    if (!stats) {
        struct enhanced_traffic_stats new_stats = {
            .packet_count = 0,
            .byte_count = 0,
            .last_update = bpf_ktime_get_ns(),
            .baseline_rate = 0,
            .deviation = 0,
            .sudden_change = 0,
            .violation_count = 0,
            .last_baseline_update = bpf_ktime_get_ns(),
            .syn_count = 0,
            .last_syn_reset = bpf_ktime_get_ns(),
            .burst_count = 0,
            .last_burst_window = bpf_ktime_get_ns(),
            .active_connections = 0,
            .last_packet_time = bpf_ktime_get_ns(),
            .malformed_packet_count = 0,
            .fragment_count = 0,
            .sequence_error_count = 0,
            .blacklist_score = 0
        };
        bpf_map_update_elem(&traffic_stats_map, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&traffic_stats_map, &key);
    }

    if (!stats)
        return XDP_DROP;

    __u64 current_time = bpf_ktime_get_ns();
    __u32 time_diff = current_time - stats->last_update;
    if (time_diff == 0) time_diff = 1;
    
    __u32 current_rate = (__u32)((stats->packet_count * 1000000000ULL) / time_diff);

    if (enhanced_dynamic_threshold(stats, current_rate, packet_size, 0, ip)) {
        return XDP_DROP;
    }

    stats->packet_count++;
    stats->byte_count += packet_size;

    return XDP_PASS;
}

static __always_inline int process_tcp(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr *tcp) {
    __u16 flags = ((__u16)tcp->fin) | ((__u16)tcp->syn << 1) | ((__u16)tcp->rst << 2) |
                  ((__u16)tcp->psh << 3) | ((__u16)tcp->ack << 4) | ((__u16)tcp->urg << 5);
    __u32 packet_size = bpf_ntohs(ip->tot_len);
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u64 conn_key = ((__u64)src_ip << 32) | dst_ip;

    __u32 *block_duration = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (block_duration) 
        return XDP_DROP;

    struct {
        __u32 prefixlen;
        __u32 ip;
    } whitelist_key;

    whitelist_key.ip = src_ip;
    whitelist_key.prefixlen = 32;

    __u32 *whitelist_val = bpf_map_lookup_elem(&whitelist_map, &whitelist_key);
    if (!whitelist_val) {
        whitelist_key.prefixlen = 24;
        whitelist_key.ip &= 0xFFFFFF00;
        whitelist_val = bpf_map_lookup_elem(&whitelist_map, &whitelist_key);
    }
    if (whitelist_val)
        return XDP_PASS;

    if (!validate_packet(ctx, ip, tcp, IPPROTO_TCP))
        return XDP_DROP;

    if (!check_tcp_flags(flags))
        return XDP_DROP;

    struct conn_info *conn = bpf_map_lookup_elem(&conntrack_map, &conn_key);
    enum conn_state state;
    
    if (!conn) {
        if (!(flags & TH_SYN)) {
            return XDP_DROP;
        }
        struct conn_info new_conn = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .state = CONN_NEW,
            .last_seen = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&conntrack_map, &conn_key, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&conntrack_map, &conn_key);
    }

    if (!conn)
        return XDP_DROP;

    state = get_conn_state(conn->state, flags);
    conn->last_seen = bpf_ktime_get_ns();
    conn->state = state;

    return dynamic_rate_limit(src_ip, src_port, packet_size);
}

static __always_inline int process_udp(struct xdp_md *ctx, struct iphdr *ip, struct udphdr *udp) {
    __u32 src_ip = ip->saddr;
    __u16 src_port = bpf_ntohs(udp->source);
    __u32 packet_size = bpf_ntohs(ip->tot_len);

    __u32 *block_duration = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (block_duration) 
        return XDP_DROP;

    if (!validate_packet(ctx, ip, udp, IPPROTO_UDP))
        return XDP_DROP;

    return dynamic_rate_limit(src_ip, src_port, packet_size);
}

static __always_inline int process_gre(struct xdp_md *ctx, struct iphdr *outer_ip, void *gre_start) {
    void *data_end = (void *)(long)ctx->data_end;
    struct gre_hdr *gre = gre_start;
    
    if ((void *)(gre + 1) > data_end)
        return XDP_DROP;

    if (!validate_packet(ctx, outer_ip, NULL, IPPROTO_GRE))
        return XDP_DROP;

    if (bpf_ntohs(gre->proto) != ETH_P_IP)
        return XDP_PASS;

    __u32 gre_header_len = sizeof(struct gre_hdr);
    if (gre->flags & GRE_CHECKSUM || gre->flags & GRE_ROUTING)
        gre_header_len += 4;
    if (gre->flags & GRE_KEY)
        gre_header_len += 4;
    if (gre->flags & GRE_SEQUENCE)
        gre_header_len += 4;

    struct iphdr *inner_ip = (void *)gre + gre_header_len;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_DROP;

    if (!validate_packet(ctx, inner_ip, NULL, 0))
        return XDP_DROP;

    if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)inner_ip + (inner_ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        if (!validate_packet(ctx, inner_ip, tcp, IPPROTO_TCP))
            return XDP_DROP;
        return process_tcp(ctx, inner_ip, tcp);
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)inner_ip + (inner_ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        if (!validate_packet(ctx, inner_ip, udp, IPPROTO_UDP))
            return XDP_DROP;
        return process_udp(ctx, inner_ip, udp);
    }

    return XDP_PASS;
}

SEC("xdp")
int tinyxdp_base(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (!validate_packet(ctx, ip, NULL, 0))
        return XDP_DROP;

    if (ip->protocol == IPPROTO_GRE) {
        void *gre_start = (void *)ip + (ip->ihl * 4);
        if (gre_start + sizeof(struct gre_hdr) > data_end)
            return XDP_DROP;
        return process_gre(ctx, ip, gre_start);
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        return process_tcp(ctx, ip, tcp);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        return process_udp(ctx, ip, udp);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
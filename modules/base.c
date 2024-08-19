#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAX_MAP_ENTRIES 131072
#define RATE_LIMIT_RESET_INTERVAL_NS 1000000000 // 1s

#define IP_NETWORK 0x258B8180  // 37.139.129.0/24

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

// TCP rate limits
#define MAX_SYN_RATE_LIMIT 1
#define MAX_SYNACK_RATE_LIMIT 60
#define MAX_ACK_RATE_LIMIT 6000
#define MAX_RST_RATE_LIMIT 1
#define MAX_FIN_RATE_LIMIT 1

// UDP rate limits
#define MAX_DNS_RATE_LIMIT 15
#define MAX_NTP_RATE_LIMIT 2
#define MAX_DHCP_RATE_LIMIT 5
#define MAX_DEFAULT_RATE_LIMIT 1000
#define MAX_UBIQUITI_RATE_LIMIT 10
#define MAX_TP240_RATE_LIMIT 5
#define MAX_PORTMAP_RATE_LIMIT 20
#define MAX_MEMCACHED_RATE_LIMIT 3
#define MAX_OPENVPN_RATE_LIMIT 50
#define MAX_NETBIOS_RATE_LIMIT 15
#define MAX_MSSQL_RATE_LIMIT 5
#define MAX_CITRIX_RATE_LIMIT 30
#define MAX_SNMP_RATE_LIMIT 10
#define MAX_QOTD_RATE_LIMIT 2
#define MAX_VXWORKS_RATE_LIMIT 5
#define MAX_XDMCP_RATE_LIMIT 5
#define MAX_SSDP_RATE_LIMIT 5
#define MAX_POWERHOUSE_RATE_LIMIT 10
#define MAX_DIGIMAN_RATE_LIMIT 5
#define MAX_SRCDS_RATE_LIMIT 20
#define MAX_STEAM_REMOTE_PLAY_RATE_LIMIT 30
#define MAX_QUAKE3_RATE_LIMIT 25
#define MAX_FIVEM_RATE_LIMIT 15
#define MAX_LANTRONIX_RATE_LIMIT 5
#define MAX_PLEX_RATE_LIMIT 20
#define MAX_ARD_RATE_LIMIT 10
#define MAX_JENKINS_RATE_LIMIT 15
#define MAX_RDP_RATE_LIMIT 40
#define MAX_STUN_RATE_LIMIT 50
#define MAX_WSD_RATE_LIMIT 10
#define MAX_DAHUA_RATE_LIMIT 5
#define MAX_BFD_RATE_LIMIT 20
#define MAX_CLDAP_RATE_LIMIT 5
#define MAX_CRESTRON_RATE_LIMIT 10
#define MAX_SLP_RATE_LIMIT 15
#define MAX_DTLS_RATE_LIMIT 30
#define MAX_IPSEC_RATE_LIMIT 25
#define MAX_MODBUS_RATE_LIMIT 20
#define MAX_SIP_RATE_LIMIT 40
#define MAX_SENTINEL_RATE_LIMIT 10
#define MAX_NETIS_RATE_LIMIT 5
#define MAX_NATPMP_RATE_LIMIT 15
#define MAX_COAP_RATE_LIMIT 20
#define MAX_BITTORRENT_DHT_RATE_LIMIT 50
#define MAX_AFS_RATE_LIMIT 10
#define MAX_HTTP_RATE_LIMIT 100
#define MAX_QUIC_RATE_LIMIT 50


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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} syn_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} sack_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} ack_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} rst_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
    });
} fin_flood_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u64);
    __type(value, struct {
        __u64 count;
        __u64 last_reset;
        __u64 packet_size_sum;
    });
} udp_flood_map SEC(".maps");

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

static __always_inline int smart_rate_limit(__u32 ip, __u16 dst_port, __u32 packet_size, __u64 max_rate_limit) {
    struct {
        __u64 count;
        __u64 last_reset;
        __u64 packet_size_sum;
    } *now;

    __u64 key = ((__u64)ip << 32) | dst_port;
    now = bpf_map_lookup_elem(&udp_flood_map, &key);
    if (!now) {
        struct {
            __u64 count;
            __u64 last_reset;
            __u64 packet_size_sum;
        } new_entry = {0, bpf_ktime_get_ns(), 0};
        bpf_map_update_elem(&udp_flood_map, &key, &new_entry, BPF_ANY);
        now = bpf_map_lookup_elem(&udp_flood_map, &key);
    }

    if (!now)
        return XDP_DROP;

    __u64 current_time = bpf_ktime_get_ns();
    if (current_time - now->last_reset >= RATE_LIMIT_RESET_INTERVAL_NS) {
        now->count = 0;
        now->last_reset = current_time;
        now->packet_size_sum = 0;
    }

    if (now->count >= max_rate_limit || now->packet_size_sum >= (max_rate_limit * 1500))
        return XDP_DROP;

    now->count++;
    now->packet_size_sum += packet_size;
    return XDP_PASS;
}

static __always_inline enum conn_state get_conn_state(enum conn_state current_state, __u16 flags) {
    switch (current_state) {
        case CONN_NEW:
            if (flags & TH_SYN)
                return CONN_SYN_SENT;
            break;
        case CONN_SYN_SENT:
            if (flags & TH_SYN && flags & TH_ACK)
                return CONN_SYN_RECEIVED;
            break;
        case CONN_SYN_RECEIVED:
            if (flags & TH_ACK)
                return CONN_ESTABLISHED;
            break;
        case CONN_ESTABLISHED:
            if (flags & TH_FIN)
                return CONN_FIN_WAIT_1;
            if (flags & TH_RST)
                return CONN_CLOSE;
            break;
        case CONN_FIN_WAIT_1:
            if (flags & TH_ACK)
                return CONN_FIN_WAIT_2;
            if (flags & TH_FIN)
                return CONN_TIME_WAIT;
            break;
        case CONN_FIN_WAIT_2:
            if (flags & TH_FIN)
                return CONN_TIME_WAIT;
            break;
        case CONN_TIME_WAIT:
            if (flags & TH_ACK)
                return CONN_CLOSE;
            break;
        case CONN_CLOSE_WAIT:
            if (flags & TH_FIN)
                return CONN_LAST_ACK;
            break;
        case CONN_LAST_ACK:
            if (flags & TH_ACK)
                return CONN_CLOSE;
            break;
        default:
            return CONN_INVALID;
    }
    return current_state;
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
    if ((flags & (TH_ACK | TH_FIN)) == TH_FIN)
        return 0;
    if ((flags & (TH_ACK | TH_URG)) == TH_URG)
        return 0;
    if ((flags & (TH_ACK | TH_FIN)) == TH_FIN)
        return 0;
    if ((flags & (TH_ACK | TH_PUSH)) == TH_PUSH)
        return 0;
    if ((flags & (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG)) == (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG))
        return 0;
    if ((flags & (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG)) == 0)
        return 0;
    if ((flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG))
        return 0;
    if ((flags & (TH_SYN | TH_FIN | TH_PUSH | TH_URG)) == (TH_SYN | TH_FIN | TH_PUSH | TH_URG))
        return 0;
    if ((flags & (TH_SYN | TH_RST | TH_ACK | TH_FIN | TH_URG)) == (TH_SYN | TH_RST | TH_ACK | TH_FIN | TH_URG))
        return 0;

    return 1;
}

static __always_inline int process_tcp(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr *tcp) {
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u64 conn_key = ((__u64)src_ip << 32) | dst_ip;


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

    __u16 flags = ((__u16)tcp->fin) | ((__u16)tcp->syn << 1) | ((__u16)tcp->rst << 2) | ((__u16)tcp->psh << 3) |
                  ((__u16)tcp->ack << 4) | ((__u16)tcp->urg << 5);
    if (check_tcp_flags(flags) == 0)
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
    } else {
        state = get_conn_state(conn->state, flags);
        conn->last_seen = bpf_ktime_get_ns();
        conn->state = state;
    }

    if (conn) {
        switch (conn->state) {
            case CONN_NEW:
                return rate_limit(src_ip, flags, MAX_SYN_RATE_LIMIT, &syn_flood_map);
            case CONN_SYN_SENT:
                return rate_limit(src_ip, flags, MAX_SYNACK_RATE_LIMIT, &sack_flood_map);
            case CONN_SYN_RECEIVED:
                return rate_limit(src_ip, flags, MAX_SYNACK_RATE_LIMIT, &sack_flood_map);
            case CONN_ESTABLISHED:
                return XDP_PASS;
            case CONN_FIN_WAIT_1:
            case CONN_FIN_WAIT_2:
            case CONN_TIME_WAIT:
                return rate_limit(src_ip, flags, MAX_FIN_RATE_LIMIT, &fin_flood_map);
            case CONN_CLOSE:
            case CONN_CLOSE_WAIT:
            case CONN_LAST_ACK:
                return rate_limit(src_ip, flags, MAX_RST_RATE_LIMIT, &rst_flood_map);
            case CONN_RELATED:
                return XDP_PASS;
            case CONN_INVALID:
            default:
                return XDP_DROP;
        }
    }
    return XDP_DROP;
}

static __always_inline int process_udp(struct xdp_md *ctx, struct iphdr *ip, struct udphdr *udp) {
    __u32 src_ip = ip->saddr;
    __u16 src_port = bpf_ntohs(udp->source);
    __u32 packet_size = bpf_ntohs(ip->tot_len);

    // Check whitelist
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

    // Apply smart rate limiting based on source port (protocol)
    switch (src_port) {
        case 53: return smart_rate_limit(src_ip, src_port, packet_size, MAX_DNS_RATE_LIMIT);
        case 123: return smart_rate_limit(src_ip, src_port, packet_size, MAX_NTP_RATE_LIMIT);
        case 67:
        case 68: return smart_rate_limit(src_ip, src_port, packet_size, MAX_DHCP_RATE_LIMIT);
        case 10001: return smart_rate_limit(src_ip, src_port, packet_size, MAX_UBIQUITI_RATE_LIMIT);
        case 10074: return smart_rate_limit(src_ip, src_port, packet_size, MAX_TP240_RATE_LIMIT);
        case 111: return smart_rate_limit(src_ip, src_port, packet_size, MAX_PORTMAP_RATE_LIMIT);
        case 11211: return smart_rate_limit(src_ip, src_port, packet_size, MAX_MEMCACHED_RATE_LIMIT);
        case 1194: return smart_rate_limit(src_ip, src_port, packet_size, MAX_OPENVPN_RATE_LIMIT);
        case 137: return smart_rate_limit(src_ip, src_port, packet_size, MAX_NETBIOS_RATE_LIMIT);
        case 1434: return smart_rate_limit(src_ip, src_port, packet_size, MAX_MSSQL_RATE_LIMIT);
        case 1604: return smart_rate_limit(src_ip, src_port, packet_size, MAX_CITRIX_RATE_LIMIT);
        case 161: return smart_rate_limit(src_ip, src_port, packet_size, MAX_SNMP_RATE_LIMIT);
        case 17: return smart_rate_limit(src_ip, src_port, packet_size, MAX_QOTD_RATE_LIMIT);
        case 17185: return smart_rate_limit(src_ip, src_port, packet_size, MAX_VXWORKS_RATE_LIMIT);
        case 177: return smart_rate_limit(src_ip, src_port, packet_size, MAX_XDMCP_RATE_LIMIT);
        case 1900: return smart_rate_limit(src_ip, src_port, packet_size, MAX_SSDP_RATE_LIMIT);
        case 20811: return smart_rate_limit(src_ip, src_port, packet_size, MAX_POWERHOUSE_RATE_LIMIT);
        case 2362: return smart_rate_limit(src_ip, src_port, packet_size, MAX_DIGIMAN_RATE_LIMIT);
        case 27015: 
        case 27016:
        case 27017: return smart_rate_limit(src_ip, src_port, packet_size, MAX_SRCDS_RATE_LIMIT);
        case 27036: return smart_rate_limit(src_ip, src_port, packet_size, MAX_STEAM_REMOTE_PLAY_RATE_LIMIT);
        case 27960: return smart_rate_limit(src_ip, src_port, packet_size, MAX_QUAKE3_RATE_LIMIT);
        case 30120: return smart_rate_limit(src_ip, src_port, packet_size, MAX_FIVEM_RATE_LIMIT);
        case 30718: return smart_rate_limit(src_ip, src_port, packet_size, MAX_LANTRONIX_RATE_LIMIT);
        case 32414: return smart_rate_limit(src_ip, src_port, packet_size, MAX_PLEX_RATE_LIMIT);
        case 3283: return smart_rate_limit(src_ip, src_port, packet_size, MAX_ARD_RATE_LIMIT);
        case 33848: return smart_rate_limit(src_ip, src_port, packet_size, MAX_JENKINS_RATE_LIMIT);
        case 3389: return smart_rate_limit(src_ip, src_port, packet_size, MAX_RDP_RATE_LIMIT);
        case 3478: return smart_rate_limit(src_ip, src_port, packet_size, MAX_STUN_RATE_LIMIT);
        case 3702: return smart_rate_limit(src_ip, src_port, packet_size, MAX_WSD_RATE_LIMIT);
        case 37810: return smart_rate_limit(src_ip, src_port, packet_size, MAX_DAHUA_RATE_LIMIT);
        case 3784: return smart_rate_limit(src_ip, src_port, packet_size, MAX_BFD_RATE_LIMIT);
        case 389: return smart_rate_limit(src_ip, src_port, packet_size, MAX_CLDAP_RATE_LIMIT);
        case 41794: return smart_rate_limit(src_ip, src_port, packet_size, MAX_CRESTRON_RATE_LIMIT);
        case 427: return smart_rate_limit(src_ip, src_port, packet_size, MAX_SLP_RATE_LIMIT);
        case 443: return smart_rate_limit(src_ip, src_port, packet_size, MAX_DTLS_RATE_LIMIT);
        case 500: return smart_rate_limit(src_ip, src_port, packet_size, MAX_IPSEC_RATE_LIMIT);
        case 502: return smart_rate_limit(src_ip, src_port, packet_size, MAX_MODBUS_RATE_LIMIT);
        case 5060: return smart_rate_limit(src_ip, src_port, packet_size, MAX_SIP_RATE_LIMIT);
        case 5093: return smart_rate_limit(src_ip, src_port, packet_size, MAX_SENTINEL_RATE_LIMIT);
        case 53413: return smart_rate_limit(src_ip, src_port, packet_size, MAX_NETIS_RATE_LIMIT);
        case 5351: return smart_rate_limit(src_ip, src_port, packet_size, MAX_NATPMP_RATE_LIMIT);
        case 5683: return smart_rate_limit(src_ip, src_port, packet_size, MAX_COAP_RATE_LIMIT);
        case 6881: return smart_rate_limit(src_ip, src_port, packet_size, MAX_BITTORRENT_DHT_RATE_LIMIT);
        case 7001: return smart_rate_limit(src_ip, src_port, packet_size, MAX_AFS_RATE_LIMIT);
        case 80: return smart_rate_limit(src_ip, src_port, packet_size, MAX_HTTP_RATE_LIMIT);
	default: return smart_rate_limit(src_ip, src_port, packet_size, MAX_DEFAULT_RATE_LIMIT);
    }
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

    if (ip->protocol == IPPROTO_TCP) {
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

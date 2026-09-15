#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} icmp_count SEC(".maps");

SEC("xdp")
int limit_icmp_req(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Ethernet Sınırı
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. IP Sınırı
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // 3. ICMP Sınırı
    struct icmphdr *icmph = (void *)(iph + 1);
    if ((void *)(icmph + 1) > data_end)
        return XDP_PASS;

    // Sadece Echo Request paketleri
    if (icmph->type == ICMP_ECHO) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&icmp_count, &key);
        if (cnt) {
            (*cnt)++;

            if (*cnt > 100)
                return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

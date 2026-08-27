#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int drop_icmp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int pkt_sz = data_end - data;
    bpf_printk("packet size is %d", pkt_sz);

    struct ethhdr *eth = data;
    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(eth + 1) > data_end) {
        bpf_printk("eth size pass");
        return XDP_PASS;
    };

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bpf_printk("protocol pass");
        return XDP_PASS;
    }

    if ((void *)(iph + 1) > data_end){
        bpf_printk("ip size pass");
        return XDP_PASS;
    };

    if (iph->protocol == IPPROTO_ICMP) {
        bpf_printk("icpm drop");
        return XDP_DROP;
    };

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
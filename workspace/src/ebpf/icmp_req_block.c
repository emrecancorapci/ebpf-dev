#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>

SEC("xdp")

int filter_icmp_req(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth +1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph -> protocol != IPPROTO_ICMP)
		return XDP_PASS;

	struct icmphdr *icmph = (void *)(iph + 1);
	if ((void *)(icmph + 1) > data_end)
		return XDP_PASS;

	if (icmph -> type == ICMP_ECHO)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

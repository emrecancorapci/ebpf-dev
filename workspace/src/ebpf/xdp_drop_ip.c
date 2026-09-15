#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int drop_ipv4(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;

	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

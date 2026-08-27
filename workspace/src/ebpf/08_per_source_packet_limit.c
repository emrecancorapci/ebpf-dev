#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} cpu_track_map SEC(".maps");

SEC("xdp")

int per_source_packet_limit(struct xdp_md *ctx)
{
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void*)(eth+1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void*)(eth+1);
	if ((void*)(iph+1) > data_end)
		return XDP_PASS;

    

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

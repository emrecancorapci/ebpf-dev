#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~csum;
}

static __always_inline __u16 icmp_csum(struct icmphdr *icmph, void *data_end)
{
	__u32 csum = 0;
	__u16 *buf = (__u16 *)icmph;

	icmph->checksum = 0;

	/* ICMP echo hdr+payload; adjust bound checks per your max payload */
	for (int i = 0; (void *)(buf + 1) > data_end || i < 100; i++) {
		csum += *buf;
		buf++;
	}

	if ((void *)buf + 1 <= data_end)
		csum += *(__u8 *)buf;

	return csum_fold_helper(csum);
}

SEC("xdp")
int exp_echo_response(struct xdp_md *ctx)
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

	if (iph->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	struct icmphdr *icmph = (void*)(iph+1);
	if ((void*)(icmph+1) > data_end)
		return XDP_PASS;

	if (icmph->type == ICMP_ECHO)
	{
        __be32 tmp_ip = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = tmp_ip;

        __u8 tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

        icmph->type = ICMP_ECHOREPLY;
	    icmph->checksum = icmp_csum(icmph, data_end);

        return XDP_TX;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

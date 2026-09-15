#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("prog")
int xdp_prog_simple(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";


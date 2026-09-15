#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_RULES);
  __type(key, __u32);
  __type(value, struct fw_rule);
} fw_rules_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_RULES);
  __type(key, __u32);
  __type(value, __u64);
} fw_rule_stats_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_IP_COUNT);
  __type(key, __be32);
  __type(value, __u64);
} fw_ip_stats_map SEC(".maps");

static __always_inline int firewall_rule_matches(const struct fw_rule *r,
                                                 __be32 src_ip, __be32 dst_ip,
                                                 __be16 src_port,
                                                 __be16 dst_port, __u8 proto) {

  return ((r->flags & FW_WILDCARD_SRC_IP) || r->src_ip == src_ip) &&
         ((r->flags & FW_WILDCARD_DST_IP) || r->dst_ip == dst_ip) &&
         ((r->flags & FW_WILDCARD_SRC_PORT) || r->src_port == src_port) &&
         ((r->flags & FW_WILDCARD_DST_PORT) || r->dst_port == dst_port) &&
         ((r->flags & FW_WILDCARD_PROTO) || r->protocol == proto);
}

SEC("xdp")
int basic_firewall(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

  if (iph->protocol != IPPROTO_ICMP)
    return XDP_PASS;

  __u8 protocol = iph->protocol;
  __be32 src_ip = iph->saddr;
  __be32 dst_ip = iph->daddr;
  __be16 src_port = 0;
  __be16 dst_port = 0;

  if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
    int ihl = iph->ihl;

    if (ihl < 5)
      return XDP_PASS;
    void *l4 = (void *)iph + ihl * 4;

    if (l4 + 4 > data_end)
      return XDP_PASS;

    src_port = *(__be16 *)l4;
    dst_port = *(__be16 *)(l4 + 2);
  }

  struct fw_rule *rule;

  for (__u32 i = 0; i < MAX_RULES; i++) {
    rule = bpf_map_lookup_elem(&fw_rules_map, &i);

    if (!rule)
      continue;

    if (firewall_rule_matches(rule, src_ip, dst_ip, src_port, dst_port,
                              protocol)) {
      __u64 *ip_stat = bpf_map_lookup_elem(&fw_ip_stats_map, &src_ip);

      if (!ip_stat) {
        __u64 val = 1;
        bpf_map_update_elem(&fw_ip_stats_map, &src_ip, &val, BPF_ANY);
      } else {
        (*ip_stat)++;
      }

      __u64 *rule_stat = bpf_map_lookup_elem(&fw_rule_stats_map, &i);

      if (rule_stat) {
        (*rule_stat)++;
      }

      return XDP_DROP;
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#pragma once

#include <linux/types.h>

#define MAX_RULES 64
#define MAX_IP_COUNT 4096

#define FW_WILDCARD_SRC_IP    (1 << 0)
#define FW_WILDCARD_SRC_PORT  (1 << 1)
#define FW_WILDCARD_DST_IP    (1 << 2)
#define FW_WILDCARD_DST_PORT  (1 << 3)
#define FW_WILDCARD_PROTO     (1 << 4)

struct fw_rule {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 flags;
};
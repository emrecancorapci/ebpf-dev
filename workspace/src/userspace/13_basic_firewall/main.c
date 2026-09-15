#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../../ebpf/13_basic_firewall/common.h"

char *ptos(__u8 proto);
void dump_rules(const struct fw_rule *rules, size_t count);
int parse_rules_file(const char *path, struct fw_rule *rules, size_t max,
                     size_t *count);

int main(int argc, char *argv[]) {
  printf("-------------------\n| RULEFILE LOADER |\n-------------------\n");

  if (argc < 2) {
    printf("Insufficient number of argument.\n");
    return -1;
  }

  struct fw_rule rules[MAX_RULES];
  size_t count = 0;

  if (parse_rules_file(argv[1], rules, MAX_RULES, &count) == -1) {
    printf("\n");
    return -1;
  }

  dump_rules(rules, count);
  printf("\nDONE: %zu rules\n", count);
};

int parse_rules_file(const char *path, struct fw_rule *rules, size_t max,
                     size_t *count) {
  FILE *fptr = fopen(path, "r");

  if (fptr == NULL) {
    printf("The file on the path (%s) is cannot opened.", path);
    return -1;
  }

  *count = 0;
  char *line = NULL;
  size_t cap = 0;
  size_t lineno = 0;

  while (getline(&line, &cap, fptr) != -1) {
    if (*count >= max) {
      printf("Rule limit (%zu) exceeded.", max);
      return -1;
    }

    lineno++;
    char *token[5], *save;

    token[0] = strtok_r(line, " \t\r\n", &save);

    if (!token[0] || token[0][0] == '#') /* blank or comment */
      continue;

    for (int i = 1; i < 5; i++) {
      token[i] = strtok_r(NULL, " \t\r\n", &save);

      if (!token[i]) {
        fprintf(stderr, "%s:%zu: expected 5 fields\n", path, lineno);
        return -1;
      }
    }

    struct fw_rule *r = &rules[(*count)++];
    memset(r, 0, sizeof(*r)); /* flags starts at 0 */

    // SRC IP
    if (strcmp(token[0], "*") == 0) {
      r->src_ip = 0;
      r->flags |= FW_WILDCARD_SRC_IP;

    } else if (inet_pton(AF_INET, token[0], &r->src_ip) != 1) {
      fprintf(stderr, "%s:%zu: bad src_ip '%s'\n", path, lineno, token[0]);
      return -1;
    }

    // DEST IP
    if (strcmp(token[1], "*") == 0) {
      r->dst_ip = 0;
      r->flags |= FW_WILDCARD_DST_IP;

    } else if (inet_pton(AF_INET, token[1], &r->dst_ip) != 1) {
      fprintf(stderr, "%s:%zu: bad dst_ip '%s'\n", path, lineno, token[1]);
      return -1;
    }

    // SRC PORT
    if (strcmp(token[2], "*") == 0) {
      r->src_port = 0;
      r->flags |= FW_WILDCARD_SRC_PORT;

    } else {
      char *end;
      unsigned long src_port = strtoul(token[2], &end, 10);

      if (end == token[2] || *end != '\0' || src_port > 65535) {
        fprintf(stderr, "%s:%zu: bad src_port '%s'\n", path, lineno, token[2]);
        return -1;

      } else {
        r->src_port = htons(src_port);
      }
    }

    // DST PORT
    if (strcmp(token[3], "*") == 0) {
      r->dst_port = 0;
      r->flags |= FW_WILDCARD_DST_PORT;

    } else {
      char *end;
      unsigned long dst_port = strtoul(token[3], &end, 10);

      if (end == token[3] || *end != '\0' || dst_port > 65535) {
        fprintf(stderr, "%s:%zu: bad dst_port '%s'\n", path, lineno, token[3]);
        return -1;

      } else {
        r->dst_port = htons(dst_port);
      }
    }

    // PROTOCOL
    if (strcmp(token[4], "*") == 0) {
      r->protocol = 0;
      r->flags |= FW_WILDCARD_PROTO;

    } else {
      if (strcasecmp("TCP", token[4]) == 0) {
        r->protocol = IPPROTO_TCP;
      } else if (strcasecmp("UDP", token[4]) == 0) {
        r->protocol = IPPROTO_UDP;
      } else {
        fprintf(stderr, "%s:%zu: bad protocol '%s'\n", path, lineno, token[4]);
        return -1;
      }
    }
  }

  return 0;
}

void dump_rules(const struct fw_rule *rules, size_t count) {
  for (size_t i = 0; i < count; i++) {
    const struct fw_rule *r = &rules[i];
    char sbuf[16], dbuf[16];

    inet_ntop(AF_INET, &r->src_ip, sbuf, sizeof(sbuf));

    printf("%2zu: %s:%u -> %s:%u %s 0x%03x\n", i,
           (r->flags & FW_WILDCARD_SRC_IP)
               ? "*"
               : inet_ntop(AF_INET, &r->src_ip, sbuf, 16),
           (r->flags & FW_WILDCARD_SRC_PORT) ? 0 : ntohs(r->src_port),
           (r->flags & FW_WILDCARD_DST_IP)
               ? "*"
               : inet_ntop(AF_INET, &r->dst_ip, dbuf, 16),
           (r->flags & FW_WILDCARD_DST_PORT) ? 0 : ntohs(r->dst_port),
           (r->flags & FW_WILDCARD_PROTO) ? "*" : ptos(r->protocol), r->flags);
  }
}

char *ptos(__u8 proto) {
  if (proto == IPPROTO_TCP) {
    return "TCP";
  } else if (proto == IPPROTO_UDP) {
    return "UDP";
  } else {
    return "UNKNOWN";
  }
}

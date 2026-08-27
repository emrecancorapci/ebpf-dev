#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <linux/if_link.h>
#include <net/if.h>

struct config {
  enum xdp_attach_mode mode;
  int ifindex;
};

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Insufficent arguments\nCommands: \"load\", \"lookup\"");
    return 0;
  };

  if (strcmp(argv[1], "load")) {
    int opt, err;
    char *file = NULL;

    struct xdp_program *prog = NULL;
    struct config cfg;

    while ((opt = getopt(argc, argv, "hf:m:i:v")) != -1) {
      switch (opt) {
      case 'm':
        if (strcmp(optarg, "skb") == 0) {
          cfg.mode = XDP_MODE_SKB;
        } else if (strcmp(optarg, "native") == 0) {
          cfg.mode = XDP_MODE_NATIVE;
        }
        break;
      case 'f':
        file = optarg;
        break;
      case 'i':
        cfg.ifindex = if_nametoindex(optarg);
        break;
      default:
        break;
      }

      if (!file) {
        fprintf(stderr, "Error: Must specify -f <bpf_object_file.o>\n");
        return 1;
      }

      prog = xdp_program__open_file(file, "xdp", NULL);

      if (libbpf_get_error(prog)) {
        fprintf(stderr, "Error: Failed to open XDP program file '%s'\n", file);
        return 1;
      }

      err = xdp_program__attach(prog, cfg.ifindex, cfg.mode, 0);
      if (err) {
        fprintf(stderr, "Error: Failed to attach XDP program (code %d)\n", err);
        xdp_program__close(prog);
        return 1;
      }
    }
  } else if (strcmp(argv[1], "lookup")) {

  }

  return 0;
}

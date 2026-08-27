#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

struct limit_info {
  __u64 pkt_cnt, bytes_cnt, limit;
};

int running = 1;
void stop(int sig) { running = 0; } // ctrl+c for exiting

int main(int argc, char **argv) {
  signal(SIGINT, stop);

  struct bpf_object *obj = bpf_object__open_file(argv[2], NULL);
  bpf_object__load(obj);

  int ifidx = if_nametoindex(argv[1]);
  bpf_xdp_attach(ifidx, bpf_program__fd(bpf_object__next_program(obj, NULL)), 0,
                 NULL);

  int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "ip_limit_map"));
  __u32 key, *prev;
  struct limit_info val;

  while (running && sleep(2) == 0) {
    for (prev = NULL; bpf_map_get_next_key(map_fd, prev, &key) == 0;
         prev = &key) {
      bpf_map_lookup_elem(map_fd, &key, &val);
      printf("%s | Pkt: %llu | Bytes: %llu\n",
             inet_ntoa(*(struct in_addr *)&key), val.pkt_cnt, val.bytes_cnt);
    }
  }
  // detach and unload
  bpf_xdp_detach(ifidx, 0, NULL);
  bpf_object__close(obj);
  printf("\nCLOSED\n");
  return 0;
}

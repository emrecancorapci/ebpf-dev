# eBPF Dev Container

A Debian (trixie) Docker container for eBPF/XDP development on a Fedora Asahi Remix
host. Runs on the host's real kernel (so BTF/CO-RE support comes for free), gets its
own IP on an isolated bridge network, and is reachable over SSH with key-based auth.

## Prerequisites

- Docker + Docker Compose v2 (`docker compose version` to check)
- Your user in the `docker` group (`sudo usermod -aG docker $(whoami)`, then
  log out/in) — otherwise every `docker` command needs `sudo`
- `/sys/kernel/btf/vmlinux` present on the host — confirms your kernel was built
  with BTF support:
  ```bash
  ls -la /sys/kernel/btf/vmlinux
  ```

## Project layout

```
ebpf-dev/
├── Dockerfile          # Debian image with clang/llvm/libbpf/bpftool + sshd
├── docker-compose.yml  # Bridge network, static IP, volumes, SSH port
├── entrypoint.sh        # Fixes SSH ownership/perms on every container start
├── setup.sh             # One-time: generates/copies your SSH public key
├── id_ed25519.pub        # Your public key, baked into the image at build time
└── workspace/            # Your code — bind-mounted, persists on the host
    ├── justfile          # Build/run recipes (see "XDP/eBPF workflow")
    ├── src/ebpf/         # XDP kernel programs
    ├── src/userspace/    # Userspace tools
    ├── build/            # Build artifacts (objects, per-tool subdirs)
    └── bin/              # Linked userspace binaries
```

## First-time setup

```bash
chmod +x setup.sh entrypoint.sh
./setup.sh
docker compose build
docker compose up -d
```

`setup.sh` only generates a new key if `~/.ssh/id_ed25519.pub` doesn't already
exist — if you already have one, it just copies it into the project folder.

## Everyday use

```bash
docker compose up -d       # start (fast — uses cached image/layers)
docker compose down        # stop and remove the container
docker compose logs -f     # follow sshd logs
```

Rebuilding after a Dockerfile change is safe on metered connections — apt
packages are cached via a BuildKit mount, so `docker compose build` won't
re-download them unless the package list itself changes:
```bash
docker compose build
docker compose up -d
```
Only use `docker compose build --no-cache` when you specifically need to force
a from-scratch rebuild (e.g. to debug a stale layer).

## Connecting

The container has its own static IP on an isolated bridge network:
**`172.28.0.10`**

```bash
ssh appuser@172.28.0.10
```

SSH is key-only (no passwords). If your key has a passphrase, load it into an
agent once per terminal session so you're not prompted repeatedly:
```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

Port `2222` on the host also forwards to the container's port 22, as a
fallback: `ssh -p 2222 appuser@localhost`.

## Networking

The container is **not** on host networking — it has its own namespace and
interface (`eth0` inside the container), attached to a dedicated bridge
(`172.28.0.0/24`). This means:

- `ping 172.28.0.10` from the host works and reflects real network behavior
- XDP/eBPF programs load onto `eth0` *inside the container*, not your real
  Wi-Fi device — safe to experiment with without risking your actual
  connection
- If a `docker compose down`/`up` cycle ever leaves the container
  disconnected from the network (rare, but has happened after editing compose
  network config on a running container), force a clean recreate:
  ```bash
  docker compose down
  docker compose up -d --force-recreate
  ```

## XDP/eBPF workflow

Inside the container, confirm the interface name (should be `eth0`):
```bash
docker compose exec ebpf-dev ip -br a
```

Build and load a program with `xdp-loader`:
```bash
just build-xdp <name>                       # src/ebpf/<name>.c -> build/<name>.o
just load-xdp <name>                        # load onto lo (edit recipe for eth0)
sudo docker compose exec ebpf-dev xdp-loader status
```

Or build+load in one step: `just run-xdp <name>`.

Test from the host against the container's IP:
```bash
ping -c 4 172.28.0.10   # should behave per your program's logic
```

Unload when done:
```bash
sudo docker compose exec ebpf-dev xdp-loader unload eth0 --all
```

### Userspace tools (`src/userspace/<name>/`)

Multi-file userspace tools are built per-directory — every `.c` compiles to
`build/<name>/<file>.o` (exact names, no collisions) and links into
`bin/<name>`:

```bash
just build-dir 11_map_lookup_ai   # build only
just run 11_map_lookup_ai ...     # run the already-built binary (sudo)
```

#### `11_map_lookup_ai` — attach + poll maps from userspace

An XDP loader/monitor that works with **any** XDP object: it pins *all* maps
from the object under `/sys/fs/bpf/<ifname>/<map_name>` (no hardcoded map
name) and polls them:

```bash
just build-xdp 11_map_lookup_kern
just run 11_map_lookup_ai load   -i eth0 -f build/11_map_lookup_kern.o -m skb
just run 11_map_lookup_ai lookup -i eth0     # Ctrl-C to stop
just run 11_map_lookup_ai unload -i eth0
```

`lookup` pretty-prints maps whose layout matches `struct limit_info`
(`__u32` key → pkt/byte counters, see `src/userspace/11_map_lookup_ai/config.h`);
other map layouts are listed but skipped. The matching kernel program is
`src/ebpf/11_map_lookup_kern.c` (LRU hash keyed by source IPv4).

Other recipes: `just status` (XDP program list), `just prog-list`
(bpftool), `just drop` (unload all from `lo`).

## Persistence

| What                         | Persists?  | Where                              |
|------------------------------|------------|-------------------------------------|
| Your code                    | Yes        | `./workspace` (bind mount)         |
| Installed apt packages       | Yes        | Baked into the image (rebuild-safe via cache mount) |
| SSH host keys                | Yes        | `ssh-host-keys` named volume       |
| Anything else written inside the container (e.g. `/tmp`, stray files outside `/workspace`) | **No** | Lost on container recreation |

Keep anything you care about inside `/workspace`.

## Troubleshooting

### SSH says "Permission denied (publickey)"

Almost always an ownership issue on `.ssh` inside the container. `entrypoint.sh`
re-asserts correct ownership on every container **start**, so this should no
longer happen after a proper rebuild. If it still does:
```bash
docker compose exec ebpf-dev cat /home/appuser/.ssh/authorized_keys
cat ~/.ssh/id_ed25519.pub
```
Confirm these match exactly. If they don't, your `id_ed25519.pub` in the
project folder is stale — re-run `./setup.sh` and rebuild.

### SSH warns "REMOTE HOST IDENTIFICATION HAS CHANGED"

Expected after an image rebuild if SSH host keys aren't persisted — clear the
stale entry:
```bash
ssh-keygen -R localhost
ssh-keygen -R 172.28.0.10
```
(Host keys are persisted in a named volume, `ssh-host-keys`, so this should
only happen if that volume gets removed.)
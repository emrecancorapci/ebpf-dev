#!/bin/bash
set -e

ls ~/.ssh/id_ed25519.pub 2>/dev/null || ssh-keygen -t ed25519 -C "ebpf-dev" -f ~/.ssh/id_ed25519 -N ""
cp ~/.ssh/id_ed25519.pub ./id_ed25519.pub
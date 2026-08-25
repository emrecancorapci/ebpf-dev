#!/bin/bash
set -e

chown -R appuser:appuser /home/appuser/.ssh
chmod 700 /home/appuser/.ssh
chmod 600 /home/appuser/.ssh/authorized_keys

exec /usr/sbin/sshd -D
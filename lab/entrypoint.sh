#!/usr/bin/env bash
# Starts the lab services. The container publishes NO ports, so none of
# this is reachable from your network.
set -euo pipefail

mkdir -p /run/sshd
/usr/sbin/sshd

# Fake "Redis" listening on every interface (just an empty TCP server)
python3 -m http.server 6379 --bind 0.0.0.0 >/dev/null 2>&1 &

exec sleep infinity

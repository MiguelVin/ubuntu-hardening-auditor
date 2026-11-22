#!/usr/bin/env bash
# Full demo: audit the vulnerable lab, fix it, audit again, save the reports.
#   bash lab/demo.sh
set -uo pipefail
cd "$(dirname "$0")"

step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

step "1/4 Building and starting a fresh vulnerable container"
docker compose up -d --build --force-recreate

step "2/4 Audit before"
docker exec -t hardaudit-lab hardaudit

step "3/4 Automatic fixes (with before/after score)"
docker exec -t hardaudit-lab hardaudit --fix --yes -o /reports

step "4/4 Copying the reports to lab/reports/"
rm -rf reports
docker cp hardaudit-lab:/reports ./reports
ls reports

echo
echo "Stop the lab with:  docker compose -f lab/docker-compose.yml down"

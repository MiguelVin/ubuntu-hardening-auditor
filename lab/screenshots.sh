#!/usr/bin/env bash
# Regenerates the README images (docs/img/*.svg) from a fresh lab container.
#   bash lab/screenshots.sh
set -uo pipefail
cd "$(dirname "$0")"

docker compose up -d --build --force-recreate
docker exec hardaudit-lab hardaudit --no-hints --screenshot /shots/audit.svg
docker exec hardaudit-lab hardaudit --fix --dry-run --no-hints --screenshot /shots/dry-run.svg
docker exec hardaudit-lab hardaudit --fix --yes --no-hints --screenshot /shots/fix.svg -o /shots

mkdir -p ../docs/img
docker cp hardaudit-lab:/shots/. ../docs/img/
rm -f ../docs/img/report.json ../docs/img/report.md  # keep only images and the HTML sample
mv ../docs/img/report.html ../docs/sample-report.html
docker compose down
ls -la ../docs ../docs/img

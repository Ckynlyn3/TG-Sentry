#!/usr/bin/env bash
# Run after test-docker.sh populates the integrity-verified upstream runtime.
# Invoke through gorun-slot.sh host mode, as documented in OPERATIONS.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"
export DOCKER_CONFIG="$ROOT/.cache/docker-empty"
NODE_IMAGE="$(/opt/homebrew/opt/node@24/bin/node -p "require('$ROOT/adapter/openclaw/upstream-lock.json').nodeImageId")"
docker run --rm --pull=never -v "$ROOT:/work" -w /work golang:1.27.2 sh -ec '
 go build -o .cache/45-aegishook ./cmd/aegishook
 go build -o .cache/openclaw/decision-fixture ./adapter/openclaw/decision-fixture.go
 sha256sum .cache/45-aegishook .cache/openclaw/decision-fixture
'
docker run --rm --pull=never -v "$ROOT:/work" -w /work "$NODE_IMAGE" bash -ec '
 mkdir -p /opt/vault45
 cp /work/.cache/45-aegishook /opt/vault45/aegishook
 chmod 700 /opt/vault45/aegishook
 node adapter/openclaw/credentials.test.mjs
'

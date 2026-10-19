#!/usr/bin/env bash
# Explicit local integration run; creates only ignored worktree .cache/node_modules.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"
export DOCKER_CONFIG="$ROOT/.cache/docker-empty"
mkdir -p "$DOCKER_CONFIG" "$ROOT/.cache/openclaw" "$ROOT/.cache/npm"
# Cached node:24 image identity is recorded in upstream-lock.json.
NODE_IMAGE="$(/opt/homebrew/opt/node@24/bin/node -p "require('$ROOT/adapter/openclaw/upstream-lock.json').nodeImageId")"
docker run --rm --name tg-sentry-issue8-verify -v "$ROOT:/work" -w /work \
  --env HOME=/work/.cache/home "$NODE_IMAGE" bash -euo pipefail -c '
  mkdir -p /work/.cache/home /opt/openclaw /opt/adapter
  node --input-type=module -e '\''
    import {readFileSync,writeFileSync} from "node:fs";
    import {createHash} from "node:crypto";
    const p=JSON.parse(readFileSync("adapter/openclaw/upstream-lock.json")).openclaw;
    const r=await fetch(p.tarball); if(!r.ok) throw Error("package download failed");
    const b=Buffer.from(await r.arrayBuffer());
    if("sha512-"+createHash("sha512").update(b).digest("base64")!==p.integrity)
      throw Error("STOP: OpenClaw integrity mismatch");
    writeFileSync(".cache/openclaw/openclaw.tgz",b);
  '\''
  tar -xzf .cache/openclaw/openclaw.tgz -C .cache/openclaw
  cp .cache/openclaw/package/package.json /opt/openclaw/
  cd /opt/openclaw
  # Named fixture exception: upstream optional OpenTelemetry peers conflict.
  # Ignore lifecycle scripts; no force installs or host/global package mutation.
  npm --userconfig=/dev/null --cache=/work/.cache/npm install --legacy-peer-deps --ignore-scripts --omit=dev --no-audit --no-fund
  cp -R node_modules package-lock.json /work/.cache/openclaw/package/
  cp /work/adapter/package*.json /opt/adapter/
  cd /opt/adapter
  npm --userconfig=/dev/null --cache=/work/.cache/npm ci --ignore-scripts --no-audit --no-fund
  cp -R node_modules /work/adapter/
  mkdir -p /work/adapter/openclaw/node_modules
  ln -sfn /work/.cache/openclaw/package /work/adapter/openclaw/node_modules/openclaw
  cd /work
  adapter/node_modules/.bin/tsc -p adapter/openclaw/tsconfig.json
  node --experimental-test-coverage --test-coverage-include="**/openclaw/index.ts" --test adapter/openclaw/plugin.test.mjs
'
docker run --rm --name tg-sentry-issue8-engine -v "$ROOT:/work" -w /work \
  -e GOCACHE=/work/.cache/go-build -e GOMODCACHE=/work/.cache/go-mod golang:1.27.2 \
  sh -ec 'go test -race ./...; go vet ./...; go build -o .cache/openclaw/decision-fixture ./adapter/openclaw/decision-fixture.go'
docker run --rm --name tg-sentry-issue8-gateway -v "$ROOT:/work" -w /work \
  --env HOME=/work/.cache/home "$NODE_IMAGE" node adapter/openclaw/gateway.test.mjs

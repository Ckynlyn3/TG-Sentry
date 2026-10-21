#!/usr/bin/env bash
# Run the real store suite without reading host Docker or database credentials.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export DOCKER_HOST=unix://${HOME}/.colima/default/docker.sock
export DOCKER_CONFIG="$root/.cache/docker-empty"
mkdir -p "$DOCKER_CONFIG" "$root/.cache/"{gomod,gobuild,home}
# Only inspect/run cached images; capture immutable IDs for this invocation.
go_image=$(docker image inspect golang:1.27.2 --format '{{.Id}}')
pg_image=$(docker image inspect postgres:16.3-alpine --format '{{.Id}}')
name="tg-sentry-wt5-$$"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
# Temp files stay container-local: the bind-mounted /workspace is a
# virtiofs/Colima share, which rejects chmod on unix sockets (EINVAL) and so
# cannot host internal/service socket tests.
common=(--pull=never --rm -v "$root:/workspace" -w /workspace
  -e GOMODCACHE=/workspace/.cache/gomod -e GOCACHE=/workspace/.cache/gobuild
  -e HOME=/workspace/.cache/home -e TMPDIR=/tmp -e GOMAXPROCS=4)
# Dependency downloads are separate from the isolated database/test network.
docker run "${common[@]}" "$go_image" sh -c 'go mod download && go list -mod=mod -deps -test ./... >/dev/null'
printf 'Go image: %s\nPostgres image: %s\n' "$go_image" "$pg_image"
docker network create --internal "$name" >/dev/null
docker run --pull=never --rm -d --name "$name" --network "$name" \
  --network-alias database -e POSTGRES_USER=test -e POSTGRES_DB=tg_sentry_test \
  -e POSTGRES_HOST_AUTH_METHOD=trust "$pg_image" >/dev/null
# No published ports or persistent volume; trust auth is confined to this
# disposable internal network, never a deployment configuration.
# The image's init server listens on the socket only (docker-library/postgres
# docker-entrypoint.sh, docker_temp_server_start: listen_addresses=''), so
# probe TCP to wait for the final server rather than the temporary one.
docker exec "$name" sh -c 'until pg_isready -h 127.0.0.1 -U test -d tg_sentry_test; do sleep 1; done'
docker exec -i "$name" psql -v ON_ERROR_STOP=1 -U test -d tg_sentry_test < "$root/internal/teststore/postgres-dev-init.sql"
if [ "$#" -eq 0 ]; then
  set -- sh -c 'go vet -p 1 ./... && go test -p 1 -race -coverpkg=./... -coverprofile=.cache/store-cover.out -json ./...'
fi
docker run "${common[@]}" --network "$name" \
  -e TG_SENTRY_TEST_DATABASE_URL='postgres://test@database/tg_sentry_test?sslmode=disable' \
  "$go_image" "$@"

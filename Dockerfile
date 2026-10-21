# Named build stages and COPY --from: https://docs.docker.com/build/building/multi-stage/
# Node 24 matches console/package.json engines and .gitlab-ci.yml's console build.
FROM node:24 AS console
# Keep the repo layout: console/e2e typechecks against ../../scripts/test-oidc.mjs (+ .d.mts).
WORKDIR /src/console
COPY scripts/test-oidc.mjs scripts/test-oidc.d.mts ../scripts/
COPY console/ ./
RUN npm ci && npm run build

FROM golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
# scripts/prepare-assets.mjs uses this same dist -> embed path; no Go changes.
# internal/assets/assets.go:5 embeds ui/*; remove stale assets before copying.
RUN rm -rf ./internal/assets/ui
COPY --from=console /src/console/dist/ ./internal/assets/ui/
RUN CGO_ENABLED=0 go build -trimpath -o /aegishook ./cmd/aegishook \
    && mkdir /data && chown 65534:65534 /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /aegishook /aegishook
# 65534 is the build image's nobody UID/GID; no root runtime or shell.
COPY --from=build --chown=65534:65534 /data /data
USER 65534:65534
ENV HOME=/data
WORKDIR /data
ENTRYPOINT ["/aegishook"]
CMD ["serve", "--addr", "127.0.0.1:18790", "--data-dir", "/data"]

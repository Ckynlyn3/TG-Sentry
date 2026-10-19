# https://docs.docker.com/build/building/multi-stage/
FROM golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
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

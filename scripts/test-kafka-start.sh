#!/usr/bin/env bash
# GitHub runner host Docker, not Docker-in-Docker; no real credentials.
set -euo pipefail
fixture=${1:?throwaway fixture directory required}
name=${2:?container name required}
network=${3:?isolated Docker network required}
mkdir -p "$fixture"
# Reuse S1's P-256 ephemeral certificate fixtures; -days 1 is OpenSSL's default.
# https://docs.openssl.org/3.0/man1/openssl-req/#options (-x509, -days, -addext)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$fixture/ca-key.pem" -out "$fixture/ca.pem" -days 1 -subj /CN=kafka-test-CA
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$fixture/server-key.pem" -out "$fixture/server.csr" -subj /CN=kafka
printf 'subjectAltName=DNS:kafka,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > "$fixture/extensions"
openssl x509 -req -in "$fixture/server.csr" -CA "$fixture/ca.pem" -CAkey "$fixture/ca-key.pem" \
  -CAcreateserial -out "$fixture/server.pem" -days 1 -extfile "$fixture/extensions"
cat "$fixture/server-key.pem" "$fixture/server.pem" > "$fixture/server-chain.pem"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$fixture/client-key.pem" -out "$fixture/client.csr" -subj /CN=kafka-test-client
printf 'extendedKeyUsage=clientAuth\n' > "$fixture/client-extensions"
openssl x509 -req -in "$fixture/client.csr" -CA "$fixture/ca.pem" -CAkey "$fixture/ca-key.pem" \
  -CAcreateserial -out "$fixture/client.pem" -days 1 -extfile "$fixture/client-extensions"
# Throwaway literals, not deployment secrets. PLAIN only over verified TLS.
printf 'fixture-password\n' > "$fixture/password"
chmod 600 "$fixture/password" "$fixture/client-key.pem" "$fixture/ca-key.pem" "$fixture/server-key.pem"
# File-input configuration: a mounted /mnt/shared/config/server.properties replaces the
# image's bundled KRaft config, per the official image guide ("It replaces the default
# KRaft configuration file present in Docker container"):
# https://github.com/apache/kafka/blob/4.2.0/docker/examples/README.md#use-input-file-for-providing-configs
# The image's KafkaDockerWrapper copies the mounted file and appends KAFKA_* env props:
# https://github.com/apache/kafka/blob/4.2.0/core/src/main/scala/kafka/docker/KafkaDockerWrapper.scala (prepareServerConfigs)
cat > "$fixture/server.properties" <<'PROPERTIES'
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9093
controller.listener.names=CONTROLLER
listeners=BROKER://:9092,CONTROLLER://:9093
advertised.listeners=BROKER://kafka:9092
listener.security.protocol.map=BROKER:SASL_SSL,CONTROLLER:SSL
inter.broker.listener.name=BROKER
sasl.enabled.mechanisms=PLAIN
sasl.mechanism.inter.broker.protocol=PLAIN
listener.name.broker.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="test" password="fixture-password" user_test="fixture-password";
ssl.keystore.type=PEM
ssl.keystore.location=/mnt/shared/config/server-chain.pem
ssl.truststore.type=PEM
ssl.truststore.location=/mnt/shared/config/ca.pem
ssl.endpoint.identification.algorithm=https
ssl.enabled.protocols=TLSv1.2,TLSv1.3
# ssl.client.auth is listener-scoped: the broker-wide key applies only to SSL
# listeners and Kafka warns it is ignored for SASL_SSL, so set it on the BROKER
# listener. The prefix is the lowercased listener NAME (ListenerName.configPrefix,
# "listener.name.<name>."), not the protocol.
# https://github.com/apache/kafka/blob/4.2.0/clients/src/main/java/org/apache/kafka/common/config/SslConfigs.java (SSL_CLIENT_AUTH_CONFIG)
# https://github.com/apache/kafka/blob/4.2.0/core/src/main/scala/kafka/network/SocketServer.scala (valuesFromThisConfigWithPrefixOverride)
listener.name.broker.ssl.client.auth=required
log.dirs=/tmp/kraft-combined-logs
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
auto.create.topics.enable=false
PROPERTIES
# Only synthetic fixtures are mounted. No host port is published (plan §5).
# The image uses UID 1000; its PEM keystore must be readable inside this fixture.
chmod 755 "$fixture"
# client.pem/client-key.pem too: the in-container openssl handshake below reads them as
# UID 1000, while the GitHub runner user owning the fixture is UID 1001; mode 600 makes
# the throwaway client key unreadable there (CI 39567422399). Colima's bind mount hid this.
chmod 644 "$fixture"/{ca.pem,server-chain.pem,server.properties,client.pem,client-key.pem}
cat > "$fixture/client.properties" <<'PROPERTIES'
security.protocol=SASL_SSL
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="test" password="fixture-password";
ssl.keystore.type=PEM
ssl.keystore.location=/mnt/shared/config/server-chain.pem
ssl.truststore.type=PEM
ssl.truststore.location=/mnt/shared/config/ca.pem
ssl.endpoint.identification.algorithm=https
PROPERTIES
chmod 644 "$fixture/client.properties"
docker run -d --name "$name" --network "$network" --network-alias kafka \
  -v "$fixture:/mnt/shared/config:ro" \
  apache/kafka:4.2.0@sha256:9516fb7634bad307d17c33b589fde9023003b0cb761374f500002b980a3149b9
# Verify the broker really runs the intended security config. The mounted file is only
# an input: if the mount is wrong or unreadable the image silently keeps its bundled
# PLAINTEXT config, so assert the effective /opt/kafka/config/server.properties it booted.
required_config() {
  docker exec "$name" grep -E "^(listeners|advertised\.listeners|listener\.security\.protocol\.map|inter\.broker\.listener\.name|listener\.name\.broker\.ssl\.client\.auth|sasl\.enabled\.mechanisms)=" /opt/kafka/config/server.properties | sort
}
want=$(sort <<'CONFIG'
listeners=BROKER://:9092,CONTROLLER://:9093
advertised.listeners=BROKER://kafka:9092
listener.security.protocol.map=BROKER:SASL_SSL,CONTROLLER:SSL
inter.broker.listener.name=BROKER
listener.name.broker.ssl.client.auth=required
sasl.enabled.mechanisms=PLAIN
CONFIG
)
for _ in $(seq 120); do
  [ "$(required_config 2>/dev/null)" = "$want" ] && break
  if [ "$(docker inspect -f '{{.State.Status}}' "$name")" != "running" ]; then
    printf 'FAIL: broker exited before applying the intended security config\n' >&2
    docker logs "$name" >&2 || true
    exit 1
  fi
  sleep 1
done
if [ "$(required_config)" != "$want" ]; then
  printf 'FAIL: effective broker config differs from the intended mTLS+SASL/PLAIN config\n--- got ---\n%s\n--- want ---\n%s\n' \
    "$(required_config)" "$want" >&2
  exit 1
fi
printf 'verified effective broker security config:\n%s\n' "$want"
# Authenticated metadata proves readiness. Reuse the CI 20-minute budget;
# run timeout in the Linux image rather than requiring GNU tools on the host.
docker exec "$name" timeout 20m bash -c 'until /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9092 --command-config /mnt/shared/config/client.properties >/dev/null 2>&1; do sleep 1; done'


# Behavioural proof the listener-scoped ssl.client.auth is honoured: a TLS 1.2 client
# presenting NO certificate must be refused with a handshake-failure alert. The
# effective-config grep only proves what was written; Kafka silently ignores a
# mis-prefixed key, and TLS 1.3 defers client-auth failure past the handshake, so pin
# TLS 1.2 where refusal surfaces as an alert.
# https://github.com/apache/kafka/blob/4.2.0/clients/src/main/java/org/apache/kafka/common/network/ChannelBuilders.java (listenerClientAuth)
handshake() {
  docker exec "$name" openssl s_client -connect kafka:9092 -CAfile /mnt/shared/config/ca.pem \
    -servername kafka -tls1_2 "$@" </dev/null >"$fixture/handshake.log" 2>&1
}
if handshake; then
  printf 'FAIL: broker accepted a TLS client without a certificate (mTLS not enforced)\n' >&2
  exit 1
fi
if ! handshake -cert /mnt/shared/config/client.pem -key /mnt/shared/config/client-key.pem; then
  printf 'FAIL: broker rejected a TLS client presenting the fixture certificate\n' >&2
  cat "$fixture/handshake.log" >&2 || true
  exit 1
fi
printf 'verified mutual TLS: no client certificate refused, fixture certificate accepted\n'

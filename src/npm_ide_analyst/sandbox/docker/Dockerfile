# src/npm_ide_analyst/sandbox/docker/Dockerfile
FROM node:22-bookworm-slim

# strace is required only for the opt-in --trace-native mode (runs under
# --cap-add SYS_PTRACE at runtime). Installed unconditionally; harmless unless
# that mode is enabled.
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/*

# Pinned Bun runtime. A real npm supply-chain family (e.g. tiaan) runs its
# payload under bun to evade node-only instrumentation; the harness re-execs
# those payloads under bun --preload, so bun must be baked in at build time
# (runtime is offline). Pinned for reproducibility; no floating "latest".
ARG BUN_VERSION=1.1.45
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip" -o /tmp/bun.zip \
 && unzip -q /tmp/bun.zip -d /tmp/bun \
 && install -m 0755 /tmp/bun/bun-linux-x64/bun /usr/local/bin/bun \
 && ln -sf /usr/local/bin/bun /usr/local/bin/bunx \
 && rm -rf /tmp/bun.zip /tmp/bun \
 && test "$(bun --version)" = "${BUN_VERSION}"

# Non-root user for detonation
RUN useradd -m -u 1000 analyst || true

# Build-time only: openssl to mint the sinkhole's self-signed TLS cert.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# Harness lives in the image (read-only rootfs at runtime)
WORKDIR /harness
COPY harness/ /harness/
# COPY preserves the build host's file modes; a restrictive umask (e.g. building
# as root on Kali) can leave these non-world-readable, so the non-root detonation
# user (uid 1000) hits EACCES loading preload.js. Force readable + dir-traversable.
RUN chmod -R a+rX /harness

# Self-signed cert for the sinkhole HTTPS responder. The detonation side runs with
# NODE_TLS_REJECT_UNAUTHORIZED=0 on an --internal (internet-less) network, so the
# CN/chain are irrelevant and this cert can never enable a real MITM.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=*" \
      -keyout /harness/sink-key.pem -out /harness/sink-cert.pem \
 && chmod 0644 /harness/sink-key.pem /harness/sink-cert.pem

# Canary/decoy secrets so theft is observable and traceable.
# Use printf (not echo) so \n is honored under dash (/bin/sh on bookworm-slim)
# and the files land as proper multi-line secrets rather than one literal line.
RUN mkdir -p /home/analyst/.ssh /home/analyst/.aws \
 && printf '%s\n' \
      '-----BEGIN OPENSSH PRIVATE KEY-----' \
      'CANARY-DO-NOT-USE' \
      '-----END OPENSSH PRIVATE KEY-----' > /home/analyst/.ssh/id_rsa \
 && printf '%s\n' \
      '[default]' \
      'aws_access_key_id=CANARYAKIA000000' \
      'aws_secret_access_key=canary000000' > /home/analyst/.aws/credentials \
 && printf '%s\n' \
      '//registry.npmjs.org/:_authToken=CANARY-NPM-TOKEN' > /home/analyst/.npmrc \
 && chown -R 1000:1000 /home/analyst

USER 1000:1000
ENV ANALYST_EVENT_LOG=/work/out/events.jsonl
# Entry is chosen at run time via command args (run-npm.js, run-vsix.js, or an
# --entrypoint override to node sinkhole.js).
ENTRYPOINT ["node", "-r", "/harness/preload.js"]

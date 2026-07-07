# src/npm_ide_analyst/sandbox/docker/Dockerfile
FROM node:22-bookworm-slim

# strace is required only for the opt-in --trace-native mode (runs under
# --cap-add SYS_PTRACE at runtime). Installed unconditionally; harmless unless
# that mode is enabled.
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/*

# Non-root user for detonation
RUN useradd -m -u 1000 analyst || true

# Harness lives in the image (read-only rootfs at runtime)
WORKDIR /harness
COPY harness/ /harness/

# Canary/decoy secrets so theft is observable and traceable
RUN mkdir -p /home/analyst/.ssh /home/analyst/.aws \
 && echo "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----" > /home/analyst/.ssh/id_rsa \
 && echo "[default]\naws_access_key_id=CANARYAKIA000000\naws_secret_access_key=canary000000" > /home/analyst/.aws/credentials \
 && echo "//registry.npmjs.org/:_authToken=CANARY-NPM-TOKEN" > /home/analyst/.npmrc \
 && chown -R 1000:1000 /home/analyst

USER 1000:1000
ENV ANALYST_EVENT_LOG=/work/out/events.jsonl
# Entry is chosen at run time via command args (run-npm.js or run-vsix.js)
ENTRYPOINT ["node", "-r", "/harness/preload.js"]

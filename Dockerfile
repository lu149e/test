# syntax=docker/dockerfile:1.7
# Reproducible build: pinned toolchain image, --locked dependencies.
# REGISTRY can point at a Docker Hub mirror, e.g. --build-arg REGISTRY=mirror.gcr.io/library
ARG REGISTRY=docker.io/library
FROM ${REGISTRY}/rust:1.94-bookworm AS build
WORKDIR /src
COPY . .
# Optional extra CA (corporate TLS-inspecting proxies): docker build --secret id=ca,src=ca.pem
RUN --mount=type=secret,id=ca,required=false \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ -f /run/secrets/ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/ca; fi; \
    cargo build --release --locked -p uad-cli && cp target/release/uad /usr/local/bin/uad

# Runtime: JRE (bundletool + keytool) with CA certificates, no compiler toolchain.
FROM ${REGISTRY}/eclipse-temurin:21-jre-noble
RUN groupadd -r -g 10001 uad && useradd -r -u 10001 -g uad -d /var/lib/uad -m uad
COPY --from=build /usr/local/bin/uad /usr/local/bin/uad
COPY deploy/uad.docker.toml /etc/uad/uad.toml
USER uad
ENV UAD_CONFIG=/etc/uad/uad.toml
VOLUME ["/var/lib/uad"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080"]
ENTRYPOINT ["uad"]
CMD ["serve", "--listen", "0.0.0.0:8080"]

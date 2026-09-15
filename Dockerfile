# ---- Rust: build the OPAQUE sidecar (Render builds on Linux; the Windows
# opaque-sidecar.exe in this folder cannot run there) ----
# NOTE: floating `slim` (latest stable), NOT a pinned old toolchain: the
# lockfile's transitive deps (askama / cargo_metadata via uniffi) keep
# raising their MSRV (1.91+ as of 2026), which broke rust:1.85-slim.
# Reproducibility still comes from Cargo.lock (compiler floats forward only).
FROM rust:slim AS rustbuild
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY core-crypto ./core-crypto
COPY opaque-sidecar ./opaque-sidecar
RUN cargo build --release -p opaque-sidecar

# ---- Python: relay server ----
FROM python:3.13-slim
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY --from=rustbuild /build/target/release/opaque-sidecar /srv/bin/opaque-sidecar
ENV OPAQUE_SIDECAR_BIN=/srv/bin/opaque-sidecar
# Render injects $PORT; default matches the spec when run elsewhere.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]

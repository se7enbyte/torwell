#!/usr/bin/env bash
# Idempotent, project-local bootstrap (Linux x86_64): Zig 0.17.0, Rust 1.99.1, pinned OpenTUI source + native lib, smoke test.
# No sudo, no profile edits, no global paths. Everything lives under .tooling/.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
T=$ROOT/.tooling
REV=dbebe5aa168ecc28f6772cfeb310e095f3b178b3
ZIG_VER=0.17.0
ZIG_SHA=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
RUST_VER=1.99.1
[ "$(uname -sm)" = "Linux x86_64" ] || { echo "bootstrap-opentui.sh supports Linux x86_64 only (see bootstrap-opentui.ps1 TODO)"; exit 1; }
mkdir -p "$T/dl" "$T/zig" "$T/src"
if [ ! -x "$T/zig/zig" ]; then
  curl -fsSL -o "$T/dl/zig.tar.xz" "https://ziglang.org/download/$ZIG_VER/zig-x86_64-linux-$ZIG_VER.tar.xz"
  echo "$ZIG_SHA  $T/dl/zig.tar.xz" | sha256sum -c -
  tar -xJf "$T/dl/zig.tar.xz" -C "$T/zig" --strip-components=1
fi
export RUSTUP_HOME=$T/rustup CARGO_HOME=$T/cargo
if [ ! -x "$CARGO_HOME/bin/rustc" ]; then
  U=https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
  curl -fsSL -o "$T/dl/rustup-init" "$U"
  want=$(curl -fsSL "$U.sha256" | cut -d' ' -f1)
  echo "$want  $T/dl/rustup-init" | sha256sum -c -
  chmod +x "$T/dl/rustup-init"
  "$T/dl/rustup-init" -y --no-modify-path --profile minimal --default-toolchain "$RUST_VER"
fi
if [ ! -d "$T/src/opentui/.git" ]; then
  git init -q "$T/src/opentui"
  git -C "$T/src/opentui" remote add origin https://github.com/anomalyco/opentui.git
fi
if [ "$(git -C "$T/src/opentui" rev-parse HEAD 2>/dev/null || true)" != "$REV" ]; then
  git -C "$T/src/opentui" fetch -q --depth 1 origin "$REV"
  git -C "$T/src/opentui" checkout -q FETCH_HEAD
fi
N=$T/src/opentui/packages/native
if [ ! -f "$N/lib/x86_64-linux/libopentui.a" ]; then
  ( . "$ROOT/scripts/env-opentui.sh"; cd "$N"; sh scripts/prepare-zig-deps.sh; zig build -Doptimize=ReleaseFast )
fi
( . "$ROOT/scripts/env-opentui.sh"; cd "$ROOT/spikes/opentui-smoke"; export CARGO_TARGET_DIR=$PWD/target
  cargo build --release --locked && cargo test --release --locked && python3 -I pty_smoke.py target/release/opentui-smoke )

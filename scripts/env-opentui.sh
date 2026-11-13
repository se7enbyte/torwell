# Source from Bash: . scripts/env-opentui.sh   (project-local toolchain; changes only this shell)
_t="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)/.tooling"
export RUSTUP_HOME="$_t/rustup" CARGO_HOME="$_t/cargo"
export RUSTUP_TOOLCHAIN=1.99.1
export ZIG_GLOBAL_CACHE_DIR="$_t/zig-cache" ZIG_LOCAL_CACHE_DIR="$_t/zig-cache-local"
export PATH="$_t/cargo/bin:$_t/zig:$PATH"
unset _t

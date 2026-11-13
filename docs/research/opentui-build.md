# OpenTUI source build and Rust smoke proof

Date 2026-11-13, Linux x86_64 (CachyOS, kernel 7.3.1). **Result: success on Linux host target.** Windows untested.

## Pinned revisions and tools (all under `.tooling/`, no sudo, no profile edits)

- OpenTUI `anomalyco/opentui` @ `dbebe5aa168ecc28f6772cfeb310e095f3b178b3` (shallow fetch by SHA), workspace version 0.8.3.
- Zig 0.17.0 (`minimum_zig_version` of `packages/native/build.zig.zon`), `zig-x86_64-linux-0.17.0.tar.xz`, SHA-256 `1cbe9df9…4e2026` matched ziglang.org index and upstream `setup-zig` action.
- Rust 1.99.1 (matches upstream `rust-toolchain.toml`) via `rustup-init`, SHA-256 `b1c8cb14…e6c55` verified against the published `.sha256`; isolated `RUSTUP_HOME`/`CARGO_HOME`, profile minimal.
- Bun was **not** needed: upstream `bun run build` only wraps `prepare-zig-deps.sh` (plain sh, unpacks vendored zig deps) + optional FFmpeg (video, skipped) + `zig build`. Bun is needed only for ABI regeneration/checks (`generate:abi`, `check:abi`), not run here.

## Commands

```sh
. scripts/env-opentui.sh            # PATH/RUSTUP_HOME/CARGO_HOME/ZIG caches, this shell only
scripts/bootstrap-opentui.sh        # idempotent: fetch, checksum, build, test
# native lib (host target only, ~4 min, ~1 GB RSS):
cd .tooling/src/opentui/packages/native && sh scripts/prepare-zig-deps.sh && zig build -Doptimize=ReleaseFast
# frontend:
cd spikes/opentui-smoke && CARGO_TARGET_DIR=$PWD/target cargo test --release --locked && cargo build --release --locked
python3 -I pty_smoke.py target/release/opentui-smoke
```

## Evidence

- Native output `packages/native/lib/x86_64-linux/`: `libopentui.a` (49 MB, sha256 `33c82cf6…fc7c5`), `libopentui.so` (32 MB), `opentui.h` sha256 `eaad4acb…267c54c` — identical to the header the Rust bindings were generated from (the Rust `build.rs` also enforces the header hash). This resolves the earlier mismatch.
- `spikes/opentui-smoke` is a standalone Cargo workspace depending by path on the pinned `opentui` crate (default `static` feature, links `libopentui.a`), with upstream `Cargo.lock` copied and `--locked` builds. `src/lib.rs`: bordered "Torwell" view, `Select` of actions, state line "Disconnected (nothing applied)", `q`/Quit exits. Presentation only.
- `cargo test --release --locked`: `tests/headless.rs::renders_and_reacts` **passes** using `opentui::testing::TestApp` (real native renderer, no terminal): asserts title, state line and all actions are in the rendered frame, then Down+Enter yields "Selected: Show plan".
- PTY run (`pty_smoke.py`, 80x24, `TERM=xterm-256color`): sent Down, Enter, `q`; process exited status 0; output contained the title and entered/left the alternate screen (`ESC[?1049h` … `ESC[?1049l`). Raw bytes did not contain the full "Selected: …" string because output is diff-rendered; that is covered by the headless test instead.
- Resulting binary links only libm, libgcc_s, libc (static OpenTUI, bundled libc++). Built with glibc 2.17 baseline per upstream target.
- Not run: upstream's own test suites, `check:abi`, FFmpeg/video, non-host targets.

## Notes / implications

- Disk: `.tooling` ≈ 1.9 GB (git-ignored); smoke `target/` ≈ 142 MB. Rebuild of the native lib is the only slow step; it is cached by `packages/native/lib` + zig caches.
- `.gitignore` already ignores `.tooling/` and `/target/`; `spikes/opentui-smoke/target` is ignored only if root workspace/target rules cover it — add `spikes/**/target/` when integrating (not edited by me).
- When integrating into the root workspace, use the same path dependency (or git dep + `OPENTUI_LIB_DIR`), keep `edition = 2024`, Rust ≥ 1.99.1 pinned in `rust-toolchain.toml`.

## Windows packaging implications (untested)

- Upstream supports `x86_64-pc-windows-msvc`/`-gnu`. Windows **always links `opentui.dll` via `opentui.lib`**; the DLL must ship beside the `.exe` (static link is not available there, MinGW/libc++ archive).
- Native lib cross-builds with Zig from Linux: `zig build -Doptimize=ReleaseFast -Dlibrary-target=x86_64-windows-gnu` (no SDK needed). Then `OPENTUI_LIB_DIR` or `lib/x86_64-windows` feeds the Rust build for an msvc/gnu target.
- Console VT mode and ConPTY are handled upstream; Ctrl+Z is not job control. A real Windows run (terminal rendering, DLL loading, Defender/signing of `opentui.dll`) is still required before any support claim.
- The proposed Windows bootstrap (`bootstrap-opentui.ps1`) is not written; only the Linux script exists.

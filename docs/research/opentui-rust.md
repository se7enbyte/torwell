# OpenTUI from Rust: feasibility (torwell)

Date of research: 2026-11-13. Scope: primary sources only (upstream repo `main`, official site). No install, no network or system changes.

## Key conclusions

1. **OpenTUI is a Zig core with a version-coupled C ABI, and upstream ships Rust bindings.** The upstream repo has `packages/rust/`, a Cargo workspace (`opentui-sys` raw FFI, `opentui` framework, `opentui-ssh`). Its README describes it as "a terminal UI framework for Rust built on OpenTUI's native renderer… without JavaScript." The crates are `publish = false`, so they are not on crates.io.
2. **Official language and runtime are TypeScript/Bun, with Zig for the renderer.** The root README says "It is written in Zig. You write TypeScript directly or through React and Solid." Development needs Bun 1.4.1+ and Zig 0.17.0. The Rust path is secondary: it links the same native library and does not need Bun or Node at run time.
3. **Rust is therefore feasible without a JS frontend, with caveats:** the Rust crates are tied to this repo's native build and header, they are not published, and the official website documents only TS/React/Solid.
4. **Platforms (per upstream Rust README and CI):** Linux x86_64 and arm64 (glibc and musl); macOS 13+ on Apple Silicon and Intel; Windows 10 1809+ on x64 and arm64 (MSVC and GNU). **Native Windows is supported; WSL is not required.** No 32-bit targets are listed.
5. **Recommended architecture:** Rust-only app using `opentui` (pinned to a specific OpenTUI commit or release), with privileged operations isolated in a separate helper process (see below). Do not adopt a TS frontend unless a required OpenTUI feature exists only in TS.

## Verified from sources

| Claim | Source |
|---|---|
| Repo is `anomalyco/opentui`, MIT, primary language TypeScript, `main` pushed 2026-11-13, ~13.8k stars | https://api.github.com/repos/anomalyco/opentui |
| Written in Zig; TS/React/Solid frontends; "OpenCode uses OpenTUI in production" | https://raw.githubusercontent.com/anomalyco/opentui/main/README.md |
| Dev needs Bun ≥1.4.1 and Zig 0.17.0 | same README |
| Rust workspace members: `opentui-sys`, `opentui`, `opentui-ssh`; version 0.8.3; all `publish = false` | https://raw.githubusercontent.com/anomalyco/opentui/main/packages/rust/Cargo.toml and `.../crates/*/Cargo.toml` |
| Rust toolchain pinned to 1.99.1 (rustfmt, clippy); edition 2024 | https://raw.githubusercontent.com/anomalyco/opentui/main/packages/rust/rust-toolchain.toml |
| Supported targets table (Linux glibc/musl, macOS, Windows, x64/arm64) | https://raw.githubusercontent.com/anomalyco/opentui/main/packages/rust/README.md |
| Crates link the native lib from `packages/native/lib/<dir>` or `OPENTUI_LIB_DIR`; they do not build it | same README |
| Linux/macOS default is static `libopentui.a`; Windows always links `opentui.dll` (ship beside the `.exe`) | same README |
| macOS build needs Xcode CLT SDK; Windows native build needs no SDK | same README |
| ABI generated from `packages/native/include/opentui.h`; `generated.rs` must not be edited; build fails on header mismatch | same README; AGENTS.md at repo root (Rust section) |
| Windows: console VT input/output enabled; ConPTY for `TerminalView`; Ctrl+Z reaches handlers | Rust README |
| Core `engines`: bun ≥1.3.14, node ≥26.4.0; optional native packages for darwin/linux (glibc+musl)/win32, x64 and arm64 | https://raw.githubusercontent.com/anomalyco/opentui/main/packages/core/package.json |
| CI jobs `rust-linux` (incl. musl static test), `rust-windows` and `rust-macos` (push-only) run `packages/rust/test.sh` | https://raw.githubusercontent.com/anomalyco/opentui/main/.github/workflows/build-core.yml |
| Native release CI builds all targets with Zig, including Windows `.dll` and Linux `.so` | https://raw.githubusercontent.com/anomalyco/opentui/main/.github/workflows/build-native.yml |
| Website describes OpenTUI as TypeScript/React/Solid on a native Zig renderer (no Rust mention on the homepage) | https://opentui.com/ |

## Tests actually executed

**None.** Local host has no `cargo`, `rustc`, `zig`, `bun`, or `node` (checked with `which`). I did not install anything. All conclusions above come from reading upstream sources, not from building or running code.

## Limitations and untested assumptions

- The Rust crates are unpublished and version-locked to the repo's native build (0.8.3). Consuming them means a git dependency plus either a local native build (Zig 0.17.0 + Bun) or prebuilt artifacts via `OPENTUI_LIB_DIR`. I did not verify that GitHub releases publish a native archive usable by Rust; the Rust README only says npm platform packages ship the shared library.
- npm platform packages ship only `libopentui.so`/`.dylib`; on Linux/macOS that requires `default-features = false` and rpath or `LD_LIBRARY_PATH` handling.
- Upstream API churn is real: the crate and ABI are pre-1.0 (0.8.3). Expect breaking changes; pin a commit.
- Not verified: Arch/CachyOS build of the native library and Rust crates; Windows and macOS runtime behavior; terminal behavior under real hardware.
- Upstream's Rust CI exists, but I did not confirm its latest run status.

## Recommended architecture

- **Frontend:** Rust binary depending on `opentui` (feature `static` on Linux/macOS; ship `opentui.dll` on Windows). Pin the dependency to a specific upstream commit matching the header.
- **Privilege separation:** keep the TUI unprivileged. Any future operation that needs elevated rights (e.g., interface or MAC changes) lives in a separate helper with a minimal, typed IPC surface (Unix domain socket with peer-credential checks on Linux/macOS; named pipe with restrictive ACL on Windows). The TUI sends requests; the helper validates and performs them. This is a design constraint, not an implementation.
- **Packaging:** Linux: glibc or musl static-linked `libopentui.a`, so no OpenTUI shared library is needed at run time. macOS: build per architecture (or universal via two builds) on macOS 13+. Windows: ship `.exe` plus `opentui.dll`.
- **Fallback:** if a required OpenTUI feature exists only in the TS packages, a TS frontend over IPC is possible (`@opentui/core` needs Bun ≥1.3.14 or Node ≥26.4), but this adds a second runtime and an IPC boundary. Avoid unless needed.

## Next step (not done here)

On a machine with Rust 1.99.1, Zig 0.17.0, and Bun 1.4.1+, run `bun install && bun run build` in the upstream checkout, then `sh packages/rust/test.sh shared` in `packages/rust`. That would be the first real verification; it was out of scope for this research pass.

## Follow-up artifact check

See [opentui-smoke.md](opentui-smoke.md): no matching prebuilt native artifact was established for the inspected Rust-binding revision. No Cargo build or render test ran. Source-build feasibility remains untested.

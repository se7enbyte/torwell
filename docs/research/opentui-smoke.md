# OpenTUI Rust smoke feasibility

Checked 2026-11-13 on Linux x86_64. This pass stopped before installing Rust or building: there is no matching official prebuilt native input for the upstream revision that contains the Rust bindings. Per scope, no Zig/source build was attempted.

## Upstream verification

- Queried `https://api.github.com/repos/anomalyco/opentui/commits/main`: current `main` was `dbebe5aa168ecc28f6772cfeb310e095f3b178b3`.
- At that commit, `packages/rust/Cargo.toml` exists and defines `opentui-sys`, `opentui`, and `opentui-ssh`, workspace version `0.8.3`. `packages/core/package.json` is also `0.8.3`.
- The matching official npm artifact `@opentui/core-linux-x64@0.8.3` reports `gitHead` `b9e9d46b9303ca3ae20d38f867d6211f2d7ecaa5`, unpacked size 8,766,570 bytes. Its source tree has `packages/native/include/opentui.h` but no `packages/rust/` (verified via the GitHub tree API). Thus this prebuilt package predates the Rust bindings.
- Header SHA-256 differs: Rust `main` header `eaad4acbfd670dd888fc6675e52449665a713f55590d1d9bc6d4b0ea8267c54c`; npm artifact's `gitHead` header `b36253ea685478ea3d75dfd8489f330c2dbce98b343f8721ae6ab98f20885a9f`. Diff includes newer public enum/constants and layout API in `main`; substituting the older native library would not establish a matching ABI.
- `@opentui/core-linux-x64@0.8.4` is not the match: its `gitHead` is `d4a2af24ba50636da5f222367f91746a1bf89644`, while inspected upstream `main` is a later commit and has version `0.8.3`. No matching prebuilt artifact was established for `dbebe5a`.

## Result

**Blocker:** the verified Rust-binding revision has no matching official prebuilt native library available from the inspected npm artifacts. The available `0.8.3` Linux x64 artifact comes from a different commit and has a different C header. Building native from source would require the Zig/Bun path expressly excluded from this economical proof. Stopped here rather than risking an ABI-mismatched executable or launching a large build.

No files were created in `spikes/opentui-smoke/`; `.tooling/` was created but no tools downloaded. No Rust frontend, Cargo build, linking, headless rendering, or runtime behavior was tested. Therefore this is an upstream artifact feasibility finding, not a Rust/OpenTUI working smoke proof. Cross-platform feasibility and terminal behavior remain untested.

## Commands and results

- `uname -sm` → `Linux x86_64`.
- `command -v cargo rustc bun node zig` → all absent; `curl` and `tar` are present.
- Queried GitHub commit, tag, recursive tree, raw manifests/headers, and npm registry metadata with `curl`; used `jq` for the metadata fields and `sha256sum`/`diff` for header comparison.
- No Rust toolchain download or build command was run because the matching-native prerequisite failed.

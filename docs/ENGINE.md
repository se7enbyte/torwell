# torwell-engine

`crates/torwell-engine` is the local helper between `torwell-ui` and the platform
backend: one request in, one response out, no shell, and the UI shows exactly that.

## CLI
```text
usage: torwell-engine [--no-escalate]
       torwell-engine restore-at-boot
       torwell-engine boot-protection enable|disable|status
(no arguments: read one JSON request from stdin, write one JSON response to stdout)
```

`-h`/`--help` prints this usage; `-V`/`--version` prints the version; any other
argument is a usage error, and no argument means protocol mode. Exit codes
(`src/reply.rs`): 0 success, 1 error response (JSON error still on stdout) or failed
subcommand, 2 misuse or root-only subcommand without root, 3 stdout write failure.

## Protocol mode
One JSON request on stdin (64 KiB / 65536 bytes max; one more is
`message_too_large`), one JSON response on stdout; diagnostics only on stderr. Unknown
fields, commands and versions other than 1 are refused.

```sh
echo '{"version":1,"command":"status"}' | torwell-engine
echo '{"version":1,"command":"inspect"}' | torwell-engine
```

Read-only commands run unprivileged and never mutate: `inspect`, `status`, `plan`; mutating commands always require root: `start`, `stop`, `switch`, `recover`.

## Privilege flow
For a mutating request with a non-zero effective uid (`src/privilege.rs`):

1. Resolve the real path from `/proc/self/exe` (never `argv[0]` or the environment).
2. Require a root-owned regular file, not group/other-writable, reached through
   root-owned non-writable directories and not a symlink. A dev build fails this and
   the request is refused with `permission_denied` before any process is spawned.
3. Run absolute `/usr/bin/pkexec <engine> --no-escalate` (argv array, no shell) with
   a cleared environment (`LC_ALL=C`), the request relayed on stdin, and a 15 minute
   timeout. The child's response is decoded and re-validated (success also needs exit
   code 0); its stderr is relayed bounded to 4 KiB.

`--no-escalate` makes the elevated child refuse instead of looping if it is not root.
pkexec exit 126 means authorization was dismissed or denied; 127 means polkit could
not authorize or run the engine (usually a missing policy); both become `permission_denied`.

Packaging installs `packaging/polkit/org.torwell.engine.policy` into
`/usr/share/polkit-1/actions/`: action `org.torwell.engine`, `exec.path`
`/usr/bin/torwell-engine`, `allow_active` `auth_admin_keep`, other defaults
`auth_admin`, `allow_gui` false.

## Boot subcommands
`restore-at-boot` is root only and is what `torwell-restore.service` runs. It calls
the backend restore path: nothing to restore, the owned table already verified, or the
blocking table re-applied and verified (Tor not started, traffic stays blocked).
Diagnostics go to stderr/journal.

`boot-protection status` is unprivileged and file-only: `enabled` when
`/etc/systemd/system/torwell-restore.service` and its `multi-user.target.wants` link
exist, `installed-not-enabled` when only the unit exists, else `not-installed`.
`enable`/`disable` require root. `enable` renders the unit from
`crates/torwell-linux/assets/torwell-restore.service` with `ExecStart=<engine>
restore-at-boot` (engine from `/proc/self/exe`), refuses a unit Torwell did not
write, writes atomically (0644), then runs `systemctl daemon-reload` and
`systemctl enable torwell-restore.service`, never `--now`. `disable` runs
`systemctl disable`, removes only the marker-carrying unit, and reloads systemd.

## Honest state
`connected` needs live evidence: persisted state says active, the process is root,
and a live check passes both nftables enforcement read-back and Tor bootstrap
(`src/map.rs`). Without it, active state is `starting` (blocked/interrupted becomes
`recovery_required`), never `connected` or `blocked`; a successful `start` also
needs its own evidence. `finalize` re-validates every response, so an unevidenced
`connected` cannot reach stdout. `linux.reboot_protection` is only called enabled
when the restore unit is installed and enabled (file presence, not a boot test).

## Verified
* 64 unit and e2e tests pass; `cargo clippy` is clean.
* `cargo check --target x86_64-pc-windows-gnu` passes; Windows answers every request
  with `engine_unavailable` and never simulates a state.
* Real runs: `status` and `inspect` requests answered unprivileged.
* A `start` request from an untrusted dev build is refused with `permission_denied`
  without invoking pkexec.
* `torwell-ui` shows the engine's real status through the PTY.

## Not verified / caveats
* Never run as root, and never through real pkexec/polkit yet.
* No real Tor start.
* In a pure TTY without a graphical polkit agent, pkexec's text agent may fight the
  full-screen TUI for the terminal; desktop agents (KDE/GNOME) are expected to work, untested.

//! Runs the real control-protocol code (`SystemEnv` cookie read + Unix-socket exchange, and
//! the `tor` module parsers) against a REAL tor binary started from torwell's own torrc.
//!
//! Opt-in: `TORWELL_TEST_TOR=/path/to/tor cargo test --test real_tor -- --nocapture`.
//! Tor runs as the current user inside a fresh `unshare -Urn` network namespace that has only
//! `lo`: it opens its loopback listeners and a control socket in a private temp dir, but has
//! no route anywhere, so nothing reaches the Tor network. (`DisableNetwork 1` cannot be used:
//! with it Tor opens no client listeners at all.) The Unix control socket is a file, so the
//! test talks to it from the host namespace. Nothing on the host is changed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use torwell_core::Config;
use torwell_linux::{tor, Env, SystemEnv};

struct Tor {
    child: Child,
    dir: PathBuf,
}

impl Drop for Tor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const T: Duration = Duration::from_secs(5);

fn start(bin: &Path, config: &Config) -> Tor {
    let dir = std::env::temp_dir().join(format!("torwell-real-tor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let run = dir.join("run");
    let data = dir.join("data");
    for d in [&dir, &run, &data] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // torwell's own rendered torrc, with only the data directory moved and the network off.
    let torrc = tor::render_torrc(config, &run)
        .lines()
        .map(|l| {
            if l.starts_with("DataDirectory ") {
                format!("DataDirectory {}", data.display())
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let torrc_path = dir.join("torrc");
    std::fs::write(&torrc_path, &torrc).unwrap();

    let lib = bin.parent().unwrap();
    let verify = Command::new(bin)
        .env("LD_LIBRARY_PATH", lib)
        .args(["--verify-config", "-f"])
        .arg(&torrc_path)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "tor rejected torwell's torrc:\n{torrc}\n{}",
        String::from_utf8_lossy(&verify.stdout)
    );
    let child = Command::new("unshare")
        .env("LD_LIBRARY_PATH", lib)
        .args([
            "-Urn",
            "sh",
            "-c",
            "ip link set lo up && exec \"$0\" -f \"$1\"",
        ])
        .arg(bin)
        .arg(&torrc_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let tor = Tor { child, dir };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !(run.join("control").exists() && run.join("control.authcookie").exists()) {
        assert!(
            Instant::now() < deadline,
            "tor never created its control socket"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    tor
}

fn exchange(env: &mut SystemEnv, run: &Path, uid: u32, cmds: &[&str]) -> Vec<tor::Reply> {
    let cookie = env
        .read_cookie(&run.join("control.authcookie"), uid)
        .unwrap();
    let req = tor::build_request(&cookie, cmds);
    let text = env
        .control_exchange(&run.join("control"), uid, req.as_bytes(), T)
        .unwrap();
    println!("--- raw reply ---\n{text}");
    let replies = tor::parse_replies(&text).unwrap();
    tor::check_replies(&replies, cmds.len()).unwrap().to_vec()
}

#[test]
fn control_protocol_against_real_tor() {
    let Some(bin) = std::env::var_os("TORWELL_TEST_TOR").map(PathBuf::from) else {
        eprintln!("SKIPPED: set TORWELL_TEST_TOR=/path/to/tor");
        return;
    };
    let config = Config {
        socks_port: 19050,
        trans_port: 19040,
        dns_port: 15353,
        ..Config::default()
    };
    let tor_proc = start(&bin, &config);
    let run = tor_proc.dir.join("run");
    let uid = unsafe { libc::geteuid() };
    let mut env = SystemEnv::new();

    let r = exchange(
        &mut env,
        &run,
        uid,
        &[
            "GETINFO net/listeners/socks",
            "GETINFO net/listeners/trans",
            "GETINFO net/listeners/dns",
            "GETINFO process/pid",
            "GETINFO status/bootstrap-phase",
        ],
    );
    for (i, (key, port)) in [
        ("net/listeners/socks", config.socks_port),
        ("net/listeners/trans", config.trans_port),
        ("net/listeners/dns", config.dns_port),
    ]
    .iter()
    .enumerate()
    {
        let v = tor::getinfo_value(&r[i], key).unwrap_or_else(|| panic!("no {key}"));
        assert!(
            tor::sole_loopback_listener(&v, *port),
            "{key} = {v:?}, expected only 127.0.0.1:{port}"
        );
    }
    let pid: u32 = tor::getinfo_value(&r[3], "process/pid")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(pid, tor_proc.child.id());
    assert_eq!(env.process_uids(pid).unwrap(), [uid; 4]);

    let phase = tor::getinfo_value(&r[4], "status/bootstrap-phase").unwrap();
    let (progress, tag) = tor::parse_bootstrap(&phase).unwrap();
    println!("bootstrap without any route: {progress}% {tag}");
    assert!(
        progress < 100,
        "no route to the Tor network, cannot be done"
    );
    assert!(!tor::bootstrap_done(&phase).unwrap());

    let r = exchange(&mut env, &run, uid, &["SIGNAL NEWNYM"]);
    assert_eq!(r.len(), 1);

    // A wrong owner must be refused before the cookie or socket is used.
    assert!(env
        .read_cookie(&run.join("control.authcookie"), uid + 1)
        .is_err());
}

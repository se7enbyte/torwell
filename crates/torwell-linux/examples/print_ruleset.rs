//! Prints the generated nft script. Used only to feed `nft -c -f -` inside a disposable
//! `unshare -Urn` namespace (see docs/LINUX.md). Never run against the host namespace.
fn main() {
    let uid: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let p = torwell_linux::rules::RuleParams {
        token: "00112233445566778899aabbccddeeff",
        tor_uid: uid,
        trans_port: 9040,
        dns_port: 5353,
    };
    print!("{}", torwell_linux::rules::ruleset(&p));
}

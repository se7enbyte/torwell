//! nftables ruleset for the single owned `inet torwell` table, plus structural
//! verification of what the kernel reports back (`nft -j list table`).
//!
//! Policy (output hook only):
//! * nat `output` (prio -100): Tor uid and loopback return untouched; IPv4 UDP/53 is
//!   redirected to Tor DNSPort; all other IPv4 TCP is redirected to Tor TransPort.
//! * filter `output` (prio 0, policy drop): accept Tor uid, accept loopback, accept flows the
//!   nat chain redirected to Tor's TransPort/DNSPort (`ct status dnat`), accept DHCPv4 client
//!   (udp 68 -> 67); reject everything else. There is deliberately NO
//!   `ct state established` accept, so existing direct flows are rejected too.
//!
//! The script contains no flush and no delete. It is applied as one `nft -f` transaction.

use serde_json::{json, Value};

pub const TABLE: &str = "torwell";
pub const NAT_CHAIN: &str = "nat_output";
pub const FILTER_CHAIN: &str = "filter_output";
pub const FORWARD_CHAIN: &str = "filter_forward";

pub struct RuleParams<'a> {
    pub token: &'a str,
    pub tor_uid: u32,
    pub trans_port: u16,
    pub dns_port: u16,
}

/// (chain, tag, rule body). Tags become `comment "torwell:<token>:<tag>"`.
fn rules(p: &RuleParams) -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            NAT_CHAIN,
            "nat-tor",
            format!("meta skuid {} return", p.tor_uid),
        ),
        (NAT_CHAIN, "nat-lo", "oifname \"lo\" return".to_string()),
        (
            NAT_CHAIN,
            "nat-dns",
            format!("meta nfproto ipv4 udp dport 53 redirect to :{}", p.dns_port),
        ),
        (
            NAT_CHAIN,
            "nat-tcp",
            format!(
                "meta nfproto ipv4 meta l4proto tcp redirect to :{}",
                p.trans_port
            ),
        ),
        (
            FILTER_CHAIN,
            "f-tor",
            format!("meta skuid {} accept", p.tor_uid),
        ),
        (FILTER_CHAIN, "f-lo", "oifname \"lo\" accept".to_string()),
        // The output hook keeps the pre-NAT route's oif, so a redirected flow still shows the
        // physical interface here, not `lo`. Without these two accepts every redirected
        // connection is rejected (verified with real packets in a namespace).
        (
            FILTER_CHAIN,
            "f-trans",
            format!(
                "meta nfproto ipv4 ip daddr 127.0.0.1 tcp dport {} ct status dnat accept",
                p.trans_port
            ),
        ),
        (
            FILTER_CHAIN,
            "f-dns",
            format!(
                "meta nfproto ipv4 ip daddr 127.0.0.1 udp dport {} ct status dnat accept",
                p.dns_port
            ),
        ),
        (
            FILTER_CHAIN,
            "f-dhcp4",
            // Root only: the DHCP client runs as root; nobody else gets a direct UDP path.
            "meta skuid 0 meta nfproto ipv4 udp sport 68 udp dport 67 accept".to_string(),
        ),
        (
            FILTER_CHAIN,
            "f-rej-tcp",
            "meta l4proto tcp reject with tcp reset".to_string(),
        ),
        (
            FILTER_CHAIN,
            "f-rej-rest",
            "reject with icmpx type admin-prohibited".to_string(),
        ),
        // VMs and containers (libvirt, docker, podman bridges) are routed through the
        // forward hook, which the output chains never see. Without this they leave with the
        // real IP while Torwell shows "connected".
        (
            FORWARD_CHAIN,
            "fwd-rej",
            "reject with icmpx type admin-prohibited".to_string(),
        ),
    ]
}

fn eq(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}

fn meta(key: &str) -> Value {
    json!({"meta": {"key": key}})
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload": {"protocol": protocol, "field": field}})
}

fn udp(field: &str) -> Value {
    payload("udp", field)
}

/// The expression array the kernel reports (`nft -j`) for each rule of [`rules`], in the
/// same order. Captured from a real nftables 1.1.7 listing in a disposable namespace
/// (`tests/fixtures/nft-1.1.7-list-table.json`). A rule whose comment is right but whose
/// expressions differ in any way fails verification.
fn expected_exprs(p: &RuleParams) -> Vec<(&'static str, &'static str, Value)> {
    let uid = json!(p.tor_uid);
    vec![
        (
            NAT_CHAIN,
            "nat-tor",
            json!([eq(meta("skuid"), uid.clone()), {"return": null}]),
        ),
        (
            NAT_CHAIN,
            "nat-lo",
            json!([eq(meta("oifname"), json!("lo")), {"return": null}]),
        ),
        (
            NAT_CHAIN,
            "nat-dns",
            json!([
                eq(meta("nfproto"), json!("ipv4")),
                eq(udp("dport"), json!(53)),
                {"redirect": {"port": p.dns_port}}
            ]),
        ),
        (
            NAT_CHAIN,
            "nat-tcp",
            json!([
                eq(meta("nfproto"), json!("ipv4")),
                eq(meta("l4proto"), json!("tcp")),
                {"redirect": {"port": p.trans_port}}
            ]),
        ),
        (
            FILTER_CHAIN,
            "f-tor",
            json!([eq(meta("skuid"), uid), {"accept": null}]),
        ),
        (
            FILTER_CHAIN,
            "f-lo",
            json!([eq(meta("oifname"), json!("lo")), {"accept": null}]),
        ),
        // nft folds `meta nfproto ipv4` into the `ip daddr` dependency when listing.
        (
            FILTER_CHAIN,
            "f-trans",
            json!([
                eq(payload("ip", "daddr"), json!("127.0.0.1")),
                eq(payload("tcp", "dport"), json!(p.trans_port)),
                {"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}},
                {"accept": null}
            ]),
        ),
        (
            FILTER_CHAIN,
            "f-dns",
            json!([
                eq(payload("ip", "daddr"), json!("127.0.0.1")),
                eq(payload("udp", "dport"), json!(p.dns_port)),
                {"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}},
                {"accept": null}
            ]),
        ),
        (
            FILTER_CHAIN,
            "f-dhcp4",
            json!([
                eq(meta("skuid"), json!(0)),
                eq(meta("nfproto"), json!("ipv4")),
                eq(udp("sport"), json!(68)),
                eq(udp("dport"), json!(67)),
                {"accept": null}
            ]),
        ),
        (
            FILTER_CHAIN,
            "f-rej-tcp",
            json!([eq(meta("l4proto"), json!("tcp")), {"reject": {"type": "tcp reset"}}]),
        ),
        (
            FILTER_CHAIN,
            "f-rej-rest",
            json!([{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}]),
        ),
        (
            FORWARD_CHAIN,
            "fwd-rej",
            json!([{"reject": {"type": "icmpx", "expr": "admin-prohibited"}}]),
        ),
    ]
}

/// Whole transaction text for `nft -f -` / `nft -c -f -`.
pub fn ruleset(p: &RuleParams) -> String {
    let mut s = String::new();
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!("add chain inet {TABLE} {NAT_CHAIN} {{ type nat hook output priority -100 ; policy accept ; }}\n"));
    s.push_str(&format!("add chain inet {TABLE} {FILTER_CHAIN} {{ type filter hook output priority 0 ; policy drop ; }}\n"));
    s.push_str(&format!("add chain inet {TABLE} {FORWARD_CHAIN} {{ type filter hook forward priority 0 ; policy drop ; }}\n"));
    for (chain, tag, body) in rules(p) {
        s.push_str(&format!(
            "add rule inet {TABLE} {chain} {body} comment \"torwell:{}:{tag}\"\n",
            p.token
        ));
    }
    s
}

pub fn expected_comments(p: &RuleParams, chain: &str) -> Vec<String> {
    rules(p)
        .into_iter()
        .filter(|(c, _, _)| *c == chain)
        .map(|(_, tag, _)| format!("torwell:{}:{tag}", p.token))
        .collect()
}

/// `true` when `nft -j list tables` output contains `inet torwell`.
pub fn table_exists(list_tables_json: &str) -> Result<bool, String> {
    let v: Value = serde_json::from_str(list_tables_json).map_err(|e| e.to_string())?;
    let items = v
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or("no nftables array")?;
    Ok(items.iter().any(|i| {
        i.get("table")
            .is_some_and(|t| t["family"] == "inet" && t["name"] == TABLE)
    }))
}

/// Ownership proof for teardown: the table holds at least one rule and every rule comment
/// starts with `torwell:<token>:`. A foreign table of the same name fails this.
pub fn owned_by(json: &str, token: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    let Some(items) = v.get("nftables").and_then(Value::as_array) else {
        return false;
    };
    let prefix = format!("torwell:{token}:");
    let mut rules = 0;
    for i in items {
        if let Some(r) = i.get("rule") {
            rules += 1;
            if !r
                .get("comment")
                .and_then(Value::as_str)
                .is_some_and(|c| c.starts_with(&prefix))
            {
                return false;
            }
        }
    }
    rules > 0
}

fn strip_handles(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("handle");
            m.values_mut().for_each(strip_handles);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_handles),
        _ => {}
    }
}

/// Structural verification of `nft -j list table inet torwell`. On success returns the
/// handle-stripped listing, a fingerprint for later tamper checks. When `fingerprint` is
/// given the stripped listing must equal it exactly.
///
/// This proves the table's shape (chains, hooks, priorities, policies, ordered rule
/// comments, and exact expressions through the fingerprint). It does not send packets.
pub fn verify_listing(
    json: &str,
    p: &RuleParams,
    fingerprint: Option<&str>,
) -> Result<String, String> {
    let mut v: Value = serde_json::from_str(json).map_err(|e| format!("bad nft json: {e}"))?;
    let items = v
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or("no nftables array")?
        .clone();
    let mut tables = 0;
    let mut chains: Vec<(String, Value)> = Vec::new();
    let mut rule_comments: Vec<(String, String)> = Vec::new();
    let mut rule_exprs: Vec<(String, Value)> = Vec::new();
    for i in &items {
        if let Some(t) = i.get("table") {
            if t["family"] != "inet" || t["name"] != TABLE {
                return Err("listing contains a foreign table".into());
            }
            tables += 1;
        } else if let Some(c) = i.get("chain") {
            chains.push((c["name"].as_str().unwrap_or("").to_string(), c.clone()));
        } else if let Some(r) = i.get("rule") {
            let comment = r
                .get("comment")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let expr = r
                .get("expr")
                .and_then(Value::as_array)
                .ok_or("rule has no expression array")?;
            if expr.is_empty() {
                return Err("rule has empty expression".into());
            }
            let chain = r["chain"].as_str().unwrap_or("").to_string();
            rule_exprs.push((chain.clone(), Value::Array(expr.clone())));
            rule_comments.push((chain, comment));
        } else if i.get("metainfo").is_none() {
            return Err("unexpected object kind (set/map/flowtable) in owned table".into());
        }
    }
    if tables != 1 || chains.len() != 3 {
        return Err(format!(
            "expected 1 table and 3 chains, found {tables} and {}",
            chains.len()
        ));
    }
    for (name, ty, hook, prio, policy) in [
        (NAT_CHAIN, "nat", "output", -100, "accept"),
        (FILTER_CHAIN, "filter", "output", 0, "drop"),
        (FORWARD_CHAIN, "filter", "forward", 0, "drop"),
    ] {
        let c = chains
            .iter()
            .find(|(n, _)| n == name)
            .ok_or(format!("chain {name} missing"))?;
        let c = &c.1;
        if c["type"] != ty || c["hook"] != hook || c["prio"] != prio || c["policy"] != policy {
            return Err(format!("chain {name} has wrong type/hook/priority/policy"));
        }
        let got: Vec<&String> = rule_comments
            .iter()
            .filter(|(ch, _)| ch == name)
            .map(|(_, c)| c)
            .collect();
        let want = expected_comments(p, name);
        if got.len() != want.len() || got.iter().zip(&want).any(|(a, b)| *a != b) {
            return Err(format!(
                "chain {name} rules differ from expected comment sequence"
            ));
        }
    }
    // Semantic check, independent of the fingerprint: every rule's expressions must be
    // exactly the expected ones. Comments alone prove nothing about what a rule does.
    for name in [NAT_CHAIN, FILTER_CHAIN, FORWARD_CHAIN] {
        let got = rule_exprs
            .iter()
            .filter(|(ch, _)| ch == name)
            .map(|(_, e)| e);
        let want = expected_exprs(p)
            .into_iter()
            .filter(|(ch, _, _)| *ch == name)
            .map(|(_, tag, e)| (tag, e));
        for (g, (tag, w)) in got.zip(want) {
            if *g != w {
                return Err(format!(
                    "rule {tag} in {name} does not match the expected expression"
                ));
            }
        }
    }
    strip_handles(&mut v);
    let stripped = serde_json::to_string(&v).map_err(|e| e.to_string())?;
    if let Some(fp) = fingerprint {
        if fp != stripped {
            return Err(
                "rule listing differs from recorded fingerprint (tampered or changed)".into(),
            );
        }
    }
    Ok(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> RuleParams<'static> {
        RuleParams {
            token: "abc123",
            tor_uid: 987,
            trans_port: 9040,
            dns_port: 5353,
        }
    }

    #[test]
    fn ruleset_has_no_flush_or_delete_and_only_owned_table() {
        let s = ruleset(&params());
        assert!(!s.contains("flush") && !s.contains("delete") && !s.contains("destroy"));
        for line in s.lines() {
            assert!(
                line.starts_with("add table inet torwell")
                    || line.starts_with("add chain inet torwell")
                    || line.starts_with("add rule inet torwell"),
                "{line}"
            );
        }
    }

    #[test]
    fn existing_connections_are_not_blanket_allowed() {
        let s = ruleset(&params());
        assert!(!s.contains("ct state"));
        assert!(!s.contains("established"));
        assert!(s.contains("policy drop"));
    }

    #[test]
    fn redirects_are_ipv4_tcp_and_udp_dns_only() {
        let s = ruleset(&params());
        assert!(s.contains("meta nfproto ipv4 meta l4proto tcp redirect to :9040"));
        assert!(s.contains("meta nfproto ipv4 udp dport 53 redirect to :5353"));
        assert_eq!(s.matches("redirect").count(), 2);
    }

    #[test]
    fn filter_exempts_exactly_tor_loopback_redirected_and_dhcp_then_rejects() {
        let s = ruleset(&params());
        let accepts: Vec<&str> = s
            .lines()
            .filter(|l| {
                l.contains(FILTER_CHAIN) && l.contains(" accept ") && l.starts_with("add rule")
            })
            .collect();
        assert_eq!(accepts.len(), 5);
        assert!(accepts[0].contains("meta skuid 987 accept"));
        assert!(accepts[1].contains("oifname \"lo\" accept"));
        assert!(accepts[2].contains("ip daddr 127.0.0.1 tcp dport 9040 ct status dnat accept"));
        assert!(accepts[3].contains("ip daddr 127.0.0.1 udp dport 5353 ct status dnat accept"));
        assert!(
            accepts[4].contains("meta skuid 0 meta nfproto ipv4 udp sport 68 udp dport 67 accept")
        );
        let last = s.lines().last().unwrap();
        assert!(last.contains("reject with icmpx"));
        // TCP reject precedes the generic reject; no accept follows any reject.
        let rej_tcp = s.find("reject with tcp reset").unwrap();
        assert!(s[rej_tcp..].lines().all(|l| !l.contains(" accept ")));
    }

    #[test]
    fn tor_uid_is_exempt_in_both_chains_and_every_rule_carries_the_token() {
        let s = ruleset(&params());
        assert_eq!(s.matches("meta skuid 987").count(), 2);
        assert_eq!(
            s.lines()
                .filter(|l| l.starts_with("add rule"))
                .filter(|l| l.contains("comment \"torwell:abc123:"))
                .count(),
            12
        );
    }

    fn listing(p: &RuleParams, tweak: impl Fn(&mut Value)) -> String {
        let mut items = vec![
            serde_json::json!({"metainfo": {"version": "1.1.7"}}),
            serde_json::json!({"table": {"family":"inet","name":"torwell","handle":1}}),
            serde_json::json!({"chain": {"family":"inet","table":"torwell","name":"nat_output","handle":1,"type":"nat","hook":"output","prio":-100,"policy":"accept"}}),
            serde_json::json!({"chain": {"family":"inet","table":"torwell","name":"filter_output","handle":2,"type":"filter","hook":"output","prio":0,"policy":"drop"}}),
            serde_json::json!({"chain": {"family":"inet","table":"torwell","name":"filter_forward","handle":3,"type":"filter","hook":"forward","prio":0,"policy":"drop"}}),
        ];
        for ch in [NAT_CHAIN, FILTER_CHAIN, FORWARD_CHAIN] {
            for (i, c) in expected_comments(p, ch).into_iter().enumerate() {
                let expr = expected_exprs(p)
                    .into_iter()
                    .filter(|(c2, _, _)| *c2 == ch)
                    .nth(i)
                    .unwrap()
                    .2;
                items.push(serde_json::json!({"rule": {"family":"inet","table":"torwell","chain":ch,"handle":10+i,"comment":c,"expr":expr}}));
            }
        }
        let mut v = serde_json::json!({"nftables": items});
        tweak(&mut v);
        v.to_string()
    }

    #[test]
    fn verify_accepts_expected_and_detects_changes() {
        let p = params();
        let fp = verify_listing(&listing(&p, |_| {}), &p, None).unwrap();
        assert!(!fp.contains("handle"));
        // Same content with different handles still matches the fingerprint.
        verify_listing(
            &listing(&p, |v| v["nftables"][5]["rule"]["handle"] = 999.into()),
            &p,
            Some(&fp),
        )
        .unwrap();
        // Policy flipped to accept.
        assert!(verify_listing(
            &listing(&p, |v| v["nftables"][3]["chain"]["policy"] =
                "accept".into()),
            &p,
            None
        )
        .is_err());
        // Forward chain opened, or removed entirely (VM/container traffic would bypass Tor).
        assert!(verify_listing(
            &listing(&p, |v| v["nftables"][4]["chain"]["policy"] =
                "accept".into()),
            &p,
            None
        )
        .is_err());
        assert!(verify_listing(
            &listing(&p, |v| {
                v["nftables"].as_array_mut().unwrap().remove(4);
            }),
            &p,
            None
        )
        .is_err());
        // Rule removed.
        assert!(verify_listing(
            &listing(&p, |v| {
                v["nftables"].as_array_mut().unwrap().pop();
            }),
            &p,
            None
        )
        .is_err());
        // Expression altered but comment kept: fingerprint catches it.
        assert!(verify_listing(
            &listing(&p, |v| v["nftables"][6]["rule"]["expr"] =
                serde_json::json!([{"accept": null}])),
            &p,
            Some(&fp)
        )
        .is_err());
        // Wrong token (foreign table with same name).
        let other = RuleParams {
            token: "zzz",
            ..params()
        };
        assert!(verify_listing(&listing(&p, |_| {}), &other, None).is_err());
    }

    const REAL: &str = include_str!("../tests/fixtures/nft-1.1.7-list-table.json");

    fn real_params() -> RuleParams<'static> {
        RuleParams {
            token: "00112233445566778899aabbccddeeff",
            tor_uid: 987,
            trans_port: 9040,
            dns_port: 5353,
        }
    }

    #[test]
    fn real_kernel_listing_verifies() {
        verify_listing(REAL, &real_params(), None).unwrap();
        assert_eq!(
            expected_exprs(&real_params()).len(),
            rules(&real_params()).len()
        );
    }

    /// Each mutation keeps every ownership comment intact; only the semantics change.
    #[test]
    fn real_listing_with_altered_semantics_is_refused_without_a_fingerprint() {
        let p = real_params();
        let mutations: [(&str, &str); 6] = [
            ("\"right\": 987", "\"right\": 0"),
            (
                "{\"redirect\": {\"port\": 9040}}",
                "{\"redirect\": {\"port\": 80}}",
            ),
            ("{\"redirect\": {\"port\": 5353}}", "{\"accept\": null}"),
            ("\"tcp reset\"", "\"icmpx\""),
            ("\"right\": \"lo\"", "\"right\": \"eth0\""),
            (
                "{\"reject\": {\"type\": \"icmpx\", \"expr\": \"admin-prohibited\"}}",
                "{\"accept\": null}",
            ),
        ];
        for (from, to) in mutations {
            assert!(REAL.contains(from), "fixture lacks {from}");
            let tampered = REAL.replacen(from, to, 1);
            assert!(
                verify_listing(&tampered, &p, None).is_err(),
                "accepted tampered listing: {from} -> {to}"
            );
        }
        // Wrong expected ports / uid are refused too.
        let other = RuleParams {
            trans_port: 9041,
            ..real_params()
        };
        assert!(verify_listing(REAL, &other, None).is_err());
        let other = RuleParams {
            tor_uid: 988,
            ..real_params()
        };
        assert!(verify_listing(REAL, &other, None).is_err());
    }

    #[test]
    fn table_exists_parses_list_tables() {
        let yes = r#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"torwell","handle":3}}]}"#;
        let no = r#"{"nftables":[{"table":{"family":"ip","name":"torwell","handle":3}},{"table":{"family":"inet","name":"other","handle":4}}]}"#;
        assert_eq!(table_exists(yes), Ok(true));
        assert_eq!(table_exists(no), Ok(false));
        assert!(table_exists("garbage").is_err());
    }
}

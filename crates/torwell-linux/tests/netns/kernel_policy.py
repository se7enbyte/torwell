#!/usr/bin/env python3
"""Packet-level policy test for the torwell nft ruleset.

MUST run inside a disposable `unshare -Urn` namespace; it refuses otherwise.
Usage: kernel_policy.py <host-netns-link> <ruleset-file> <trans_port> <dns_port>

Topology: `lo` plus a `dummy0` device holding 10.9.9.1/24 and fd00:9::1/64. Packets sent to
10.9.9.9 / fd00:9::9 leave through dummy0 and vanish. A separate `inet observe` table at
output priority 100 (after torwell's filter at 0) counts what still leaves via dummy0, i.e.
what would have leaked. Fake Tor TransPort/DNSPort listeners sit on 127.0.0.1.

This tests kernel policy only. It does not run Tor and proves nothing about anonymity.
Prints one JSON object with every check and exits non-zero if any failed.
"""
import json
import os
import socket
import subprocess
import sys
import threading

host_ns, ruleset_path, trans_port, dns_port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
own_ns = os.readlink("/proc/self/ns/net")
if own_ns == host_ns:
    sys.exit("refusing: not inside a separate network namespace")


def sh(*args, stdin=None):
    subprocess.run(args, input=stdin, check=True, capture_output=True, text=True)


sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "dummy0", "type", "dummy")
sh("ip", "link", "set", "dummy0", "up")
sh("ip", "addr", "add", "10.9.9.1/24", "dev", "dummy0")
sh("ip", "-6", "addr", "add", "fd00:9::1/64", "dev", "dummy0", "nodad")
sh("nft", "-f", "-", stdin="""
table inet observe {
  counter leaked_v4 {}
  counter leaked_v6 {}
  counter leaked_udp_flow {}
  counter leaked_forward {}
  chain vmfwd { type filter hook forward priority 100; policy accept;
    oifname "dummy0" counter name leaked_forward
  }
  chain out { type filter hook output priority 100; policy accept;
    oifname "dummy0" udp dport 7777 counter name leaked_udp_flow
    oifname "dummy0" meta nfproto ipv4 counter name leaked_v4
    oifname "dummy0" meta nfproto ipv6 counter name leaked_v6
  }
}
""")


def counter(name):
    out = subprocess.run(["nft", "-j", "list", "counter", "inet", "observe", name],
                         check=True, capture_output=True, text=True).stdout
    for item in json.loads(out)["nftables"]:
        if "counter" in item:
            return item["counter"]["packets"]
    raise RuntimeError("counter missing")


# A "VM": a TUN device standing in for a libvirt/docker guest. Packets written into it
# arrive from 10.8.8.2 and are routed (forwarded) out through dummy0, never passing the
# output hook. (veth would need a kernel module an unprivileged namespace cannot load.)
import fcntl
import struct

TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000
tun = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(tun, TUNSETIFF, struct.pack("16sH", b"vm0", IFF_TUN | IFF_NO_PI))
sh("ip", "addr", "add", "10.8.8.1/24", "dev", "vm0")
sh("ip", "link", "set", "vm0", "up")
with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
    f.write("1")


def csum(data):
    if len(data) % 2:
        data += b"\0"
    t = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    t = (t >> 16) + (t & 0xFFFF)
    t += t >> 16
    return ~t & 0xFFFF


def ipv4(proto, payload, src="10.8.8.2", dst="10.9.9.9"):
    s4, d4 = socket.inet_aton(src), socket.inet_aton(dst)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s4, d4)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr, s4, d4, payload


def udp_packet(dport):
    body = b"vm"
    u = struct.pack("!HHHH", 40000, dport, 8 + len(body), 0) + body
    hdr, s4, d4, _ = ipv4(17, u)
    c = csum(s4 + d4 + struct.pack("!BBH", 0, 17, len(u)) + u)
    return hdr + u[:6] + struct.pack("!H", c) + u[8:]


def tcp_syn(dport):
    t = struct.pack("!HHIIBBHHH", 40001, dport, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
    hdr, s4, d4, _ = ipv4(6, t)
    c = csum(s4 + d4 + struct.pack("!BBH", 0, 6, len(t)) + t)
    return hdr + t[:16] + struct.pack("!H", c) + t[18:]


def vm_traffic():
    for pkt in (udp_packet(9999), udp_packet(53), udp_packet(443), tcp_syn(443), tcp_syn(80)):
        os.write(tun, pkt)
    import time
    time.sleep(0.2)


# A pre-existing "connected" UDP flow (conntrack-tracked) opened before enforcement.
flow = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flow.connect(("10.9.9.9", 7777))
flow.send(b"before")
before_flow = counter("leaked_udp_flow")
vm_traffic()
fwd_before = counter("leaked_forward")

sh("nft", "-f", ruleset_path)

# Fake Tor listeners.
tcp_hits, dns_hits = [], []
tl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tl.bind(("127.0.0.1", trans_port))
tl.listen(4)
ul = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ul.bind(("127.0.0.1", dns_port))
ul.settimeout(2)


def accept_one():
    tl.settimeout(2)
    try:
        c, _ = tl.accept()
        # SO_ORIGINAL_DST (80) gives the pre-redirect destination.
        raw = c.getsockopt(socket.SOL_IP, 80, 16)
        tcp_hits.append(socket.inet_ntoa(raw[4:8]) + ":" + str(int.from_bytes(raw[2:4], "big")))
        c.close()
    except OSError as e:
        tcp_hits.append("error:" + str(e))


t = threading.Thread(target=accept_one)
t.start()
results = {}
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.settimeout(2)
try:
    c.connect(("10.9.9.9", 80))
    results["tcp_redirected_to_transport"] = True
except OSError as e:
    results["tcp_redirected_to_transport"] = False
    results["tcp_error"] = str(e)
c.close()
t.join()
results["tcp_original_dst_seen_by_listener"] = tcp_hits == ["10.9.9.9:80"]

q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    q.sendto(b"dns?", ("10.9.9.9", 53))
    data, _ = ul.recvfrom(64)
    results["udp53_redirected_to_dnsport"] = data == b"dns?"
except OSError:
    results["udp53_redirected_to_dnsport"] = False


def try_send(family, addr, kind):
    s = socket.socket(family, kind)
    s.settimeout(1)
    try:
        if kind == socket.SOCK_STREAM:
            s.connect(addr)
        else:
            s.sendto(b"x", addr)
    except OSError:
        pass
    finally:
        s.close()


v4_before, v6_before = counter("leaked_v4"), counter("leaked_v6")
try_send(socket.AF_INET, ("10.9.9.9", 9999), socket.SOCK_DGRAM)
try_send(socket.AF_INET, ("10.9.9.9", 123), socket.SOCK_DGRAM)
results["arbitrary_udp_v4_blocked"] = counter("leaked_v4") == v4_before
try_send(socket.AF_INET6, ("fd00:9::9", 443), socket.SOCK_STREAM)
try_send(socket.AF_INET6, ("fd00:9::9", 53), socket.SOCK_DGRAM)
try_send(socket.AF_INET6, ("fd00:9::9", 9999), socket.SOCK_DGRAM)
results["ipv6_tcp_udp_dns_blocked"] = counter("leaked_v6") == v6_before

try:
    flow.send(b"after")
except OSError:
    pass
vm_traffic()
results["vm_traffic_was_forwarded_before_enforcement"] = fwd_before > 0
results["vm_traffic_blocked_after_enforcement"] = counter("leaked_forward") == fwd_before
os.close(tun)
results["preexisting_flow_had_leaked_before_enforcement"] = before_flow == 1
results["preexisting_flow_blocked_after_enforcement"] = counter("leaked_udp_flow") == before_flow

print(json.dumps({"netns": own_ns, "checks": results}))
sys.exit(0 if all(v is True for k, v in results.items() if not k.endswith("_error")) else 1)

#!/usr/bin/env python3
"""Interactive network audit and export TUI for Crostini/WireGuard.

    sudo netaudit                 interactive TUI
    sudo netaudit --plain         one-shot text report
    sudo netaudit --json          one-shot JSON report
    sudo netaudit --export FMTS   export json,md,txt,html,csv,bundle [--out DIR]
    netaudit --selftest           parser/export self-test (no root or network)

Flags: --offline, --no-redact, --readonly, --name HOST.
Exit code: 0 = no FAIL, 1 = at least one FAIL.
Quote wildcard patterns to prevent shell pathname expansion, e.g. --export '*'.
"""

import argparse
import concurrent.futures as cf
import csv
import curses
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import html
import io
import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.request

VERSION = "1.0.0"
WG_IF, WG_CONF = "wg0", "/etc/wireguard/wg0.conf"
GW_FALLBACK = "100.115.92.193"
EXTRA_RESOLVERS = [
    "1.1.1.1",
    "9.9.9.9",
    "8.8.8.8",
    "194.242.2.2",
]
TCP_TARGETS = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
    ("9.9.9.9", 443),
    ("1.1.1.1", 853),
]
SEV = {"FAIL": 4, "WARN": 3, "OK": 2, "INFO": 1, "SKIP": 0}
NETISH = re.compile(
    r"\b(ip (route|rule|link|addr)|resolv\w*|wg\w*|"
    r"wireguard\w*|nft|iptables|dhclient|networkctl|"
    r"systemctl|ifup|ifdown|ping|dig|curl|tee|"
    r"sed -i|ln -sf|rm -f|netaudit)\b",
    re.I,
)


# ----------------------------------------------------------------------------- helpers
def sh(args, timeout=8, inp=None):
    try:
        p = subprocess.run(
            args, input=inp, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except FileNotFoundError:
        return 127, f"{args[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]}: timed out after {timeout}s"
    except Exception as e:
        return 1, f"{args[0]}: {type(e).__name__}: {e}"


REDACT = [
    (
        re.compile(r"(?im)^(\s*(?:PrivateKey|PresharedKey)\s*=\s*).+$"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{20,}\b|github_pat_[A-Za-z0-9_]{20,}"
        ),
        "[REDACTED-TOKEN]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS]"),
    (
        re.compile(
            r"(?i)\b(bearer|token|passw(?:or)?d|secret|api[_-]?key)(\s*[=:]\s*)\S+"
        ),
        r"\1\2[REDACTED]",
    ),
]


def redact(s):
    for rx, rep in REDACT:
        s = rx.sub(rep, s)
    return s


def redact_obj(o):
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [redact_obj(v) for v in o]
    return o


def real_user():
    name = (
        os.environ.get("SUDO_USER")
        or os.environ.get("USER")
        or pwd.getpwuid(os.getuid()).pw_name
    )
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        pw = pwd.getpwuid(os.getuid())
    return pw.pw_name, pw.pw_uid, pw.pw_gid, pw.pw_dir


class Ctx:
    def __init__(
        self, name="github.com", offline=False, redact_on=True, readonly=False
    ):
        self.name, self.offline, self.redact_on, self.readonly = (
            name,
            offline,
            redact_on,
            readonly,
        )
        self.is_root = os.geteuid() == 0
        self.user, self.uid, self.gid, self.home = real_user()
        self._gw, self.lock = None, threading.Lock()

    def gateway(self):
        with self.lock:
            if self._gw:
                return self._gw
            gw = None
            rc, out = sh(["ip", "-4", "route", "show", "default"])
            m = re.search(r"default via (\S+) dev eth0", out)
            if m:
                gw = m.group(1)
            if not gw:
                rc, out = sh(["ip", "-4", "-o", "addr", "show", "dev", "eth0"])
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
                if m:
                    try:
                        gw = str(
                            ipaddress.ip_interface(
                                m.group(1)
                            ).network.network_address
                            + 1
                        )
                    except ValueError:
                        gw = None
            self._gw = gw or GW_FALLBACK
            return self._gw


@dataclasses.dataclass
class Result:
    id: str
    title: str
    status: str = "SKIP"
    summary: str = ""
    detail: str = ""
    data: dict = dataclasses.field(default_factory=dict)
    secs: float = 0.0


def parse_ping(out):
    d = {"tx": None, "rx": None, "loss": None, "avg": None}
    m = re.search(
        r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss",
        out,
    )
    if m:
        d["tx"], d["rx"], d["loss"] = int(m[1]), int(m[2]), float(m[3])
    m = re.search(r"= [\d.]+/([\d.]+)/", out)
    if m:
        d["avg"] = float(m[1])
    return d


def parse_wg_conf(path):
    d = {"path": path, "exists": os.path.exists(path), "readable": False}
    if not d["exists"]:
        return d
    try:
        text = open(path).read()
    except PermissionError:
        return d
    except OSError as e:
        d["error"] = str(e)
        return d
    d["readable"] = True
    sec, iface, peers, cur = None, {}, [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            sec = line.strip("[]").lower()
            if sec == "peer":
                cur = {}
                peers.append(cur)
            continue
        if "=" not in line:
            continue
        k, v = [x.strip() for x in line.split("=", 1)]
        (cur if sec == "peer" and cur is not None else iface)[k.lower()] = v
    priv = iface.pop(
        "privatekey", None
    )  # secret: used only to derive the public key, never stored
    d["has_privatekey"] = bool(priv)
    own = None
    if priv:
        rc, out = sh(["wg", "pubkey"], inp=priv + "\n")
        own = out.strip() if rc == 0 and len(out.strip()) == 44 else None
    for p in peers:
        p.pop("presharedkey", None)
    d.update(own_pub=own, interface=iface, peers=peers)
    d["peer_is_own_key"] = bool(own) and any(
        p.get("publickey") == own for p in peers
    )
    d["table_off"] = iface.get("table", "").lower() == "off"
    d["has_postup"] = "postup" in iface
    ep = peers[0].get("endpoint", "") if peers else ""
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)$", ep)
    d["endpoint_ip"], d["endpoint_port"] = (
        (m.group(1), m.group(2)) if m else (None, None)
    )
    try:
        d["mode"] = oct(os.stat(path).st_mode & 0o777)
    except OSError:
        pass
    return d


def resolv_state():
    p = "/etc/resolv.conf"
    if os.path.islink(p) and not os.path.exists(p):
        return "dangling", [], os.readlink(p)
    if not os.path.exists(p):
        return "missing", [], ""
    try:
        txt = open(p).read()
    except OSError:
        return "unreadable", [], ""
    ns = re.findall(r"(?m)^\s*nameserver\s+(\S+)", txt)
    return ("ok" if ns else "empty"), ns, txt


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError(
                "connection closed before response was complete"
            )
        data.extend(chunk)
    return bytes(data)


def dns_query(ns, name, proto, timeout=2.0, port=53):
    tid = os.urandom(2)
    q = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += (
        b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        + b"\x00\x00\x01\x00\x01"
    )
    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(q, (ns, port))
                r = s.recv(512)
        else:
            with socket.create_connection((ns, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(struct.pack(">H", len(q)) + q)
                ln = struct.unpack(">H", recv_exact(s, 2))[0]
                r = recv_exact(s, ln)
        if len(r) < 12:
            return "short-response"
        if r[:2] != tid:
            return "bad-id"
        rc, an = r[3] & 15, struct.unpack(">H", r[6:8])[0]
        return "ok" if rc == 0 and an > 0 else f"rcode={rc},an={an}"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except Exception as e:
        return type(e).__name__


# ----------------------------------------------------------------------------- checks
# each returns (status, summary, detail, data)
def check_system(ctx):
    pretty = ""
    try:
        m = re.search(
            r'PRETTY_NAME="?([^"\n]+)', open("/etc/os-release").read()
        )
        pretty = m.group(1) if m else ""
    except OSError:
        pass
    rc, virt = sh(["systemd-detect-virt"])
    rc2, p1 = sh(["ps", "-o", "lstart=", "-p", "1"])
    lines = [
        f"time        : {dt.datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"user        : {ctx.user} (uid {ctx.uid}), running as {'ROOT' if ctx.is_root else 'non-root'}",
        f"os          : {pretty}",
        f"kernel      : {' '.join(os.uname()[0:3])}",
        f"virt        : {virt}",
        f"PID 1 start : {p1 if rc2 == 0 else 'n/a'}",
    ]
    return (
        "INFO",
        f"{pretty or 'linux'}, {'root' if ctx.is_root else 'non-root (limited)'}",
        "\n".join(lines),
        {"root": ctx.is_root},
    )


def check_routes(ctx):
    rc, out = sh(["ip", "-4", "route", "show"])
    if rc == 127:
        return "SKIP", "ip not installed", out, {}
    rows = []
    for line in out.splitlines():
        t = line.split()
        if not t:
            continue
        via = t[t.index("via") + 1] if "via" in t else None
        dev = t[t.index("dev") + 1] if "dev" in t else None
        rows.append({"dest": t[0], "via": via, "dev": dev})
    defaults = [r for r in rows if r["dest"] in ("default", "0.0.0.0/0")]
    split = {r["dest"] for r in rows if r["dev"] == WG_IF} >= {
        "0.0.0.0/1",
        "128.0.0.0/1",
    }
    rc2, eff = sh(["ip", "-4", "route", "get", "1.1.1.1"])
    m = re.search(r"\bdev (\S+)", eff)
    eff_dev = m.group(1) if (m and rc2 == 0) else None
    unreachable = rc2 != 0
    data = {
        "defaults": defaults,
        "no_default": not defaults,
        "eff_dev": eff_dev,
        "unreachable": unreachable,
        "split_wg": split,
    }
    detail = out + "\n\n--- ip route get 1.1.1.1 ---\n" + eff
    if unreachable:
        return (
            "FAIL",
            "no route to 1.1.1.1 (Network is unreachable)",
            detail,
            data,
        )
    if eff_dev == WG_IF:
        return (
            "INFO",
            f"internet exits via {WG_IF}"
            + (" (split /1 routes)" if split else ""),
            detail,
            data,
        )
    return "OK", f"1.1.1.1 via {eff_dev}", detail, data


def check_gateway(ctx):
    gw = ctx.gateway()
    rc, out = sh(["ping", "-c", "2", "-W", "2", gw], timeout=10)
    if rc == 127:
        return "SKIP", "ping not installed", out, {}
    p = parse_ping(out)
    rc2, neigh = sh(["ip", "neigh", "show", "to", gw, "dev", "eth0"])
    state = neigh.split()[-1] if neigh.split() else "?"
    data = dict(p, gw=gw, neigh=state)
    detail = out + "\n\nneighbour: " + (neigh or "none")
    if p["rx"]:
        return (
            "OK",
            f"{gw} replies ({p['avg']} ms, neighbour {state})",
            detail,
            data,
        )
    return "FAIL", f"{gw} does not answer (neighbour {state})", detail, data


def check_icmp(ctx):
    rc, out = sh(["ping", "-c", "3", "-W", "2", "1.1.1.1"], timeout=14)
    if rc == 127:
        return "SKIP", "ping not installed", out, {}
    p = parse_ping(out)
    if p["rx"] is None:
        return (
            "FAIL",
            out.splitlines()[-1][:60] if out else "no ping output",
            out,
            p,
        )
    if p["rx"] == p["tx"]:
        return "OK", f"1.1.1.1: 0% loss, avg {p['avg']} ms", out, p
    if p["rx"] > 0:
        return "WARN", f"1.1.1.1: {p['loss']}% loss", out, p
    return "FAIL", "1.1.1.1: 100% loss", out, p


def check_resolv(ctx):
    state, ns, extra = resolv_state()
    data = {"state": state, "nameservers": ns}
    if state == "dangling":
        return (
            "FAIL",
            f"/etc/resolv.conf is a dangling symlink -> {extra}",
            "",
            data,
        )
    if state in ("missing", "empty", "unreadable"):
        return "FAIL", f"/etc/resolv.conf {state}", "", data
    warn = [n for n in ns if n.startswith("10.64.")]
    rc, link = sh(["ip", "link", "show", WG_IF])
    if warn and rc != 0:
        return (
            "WARN",
            f"points at Mullvad-internal DNS {warn[0]} but {WG_IF} is down",
            extra,
            data,
        )
    return "OK", "nameservers: " + ", ".join(ns), extra, data


def check_dns(ctx):
    state, ns, _ = resolv_state()
    cands = []
    for n in ns + [ctx.gateway()] + EXTRA_RESOLVERS:
        try:
            if ipaddress.ip_address(n).version == 4 and n not in cands:
                cands.append(n)
        except ValueError:
            pass
    with cf.ThreadPoolExecutor(max_workers=len(cands) * 2 + 1) as ex:
        sysf = ex.submit(sh, ["getent", "hosts", ctx.name], 8)
        futs = {
            (n, p): ex.submit(dns_query, n, ctx.name, p)
            for n in cands
            for p in ("udp", "tcp")
        }
        rc, sysout = sysf.result()
        res = {k: f.result() for k, f in futs.items()}
    rows = [
        f"{n:<16} udp:{res[(n, 'udp')]:<14} tcp:{res[(n, 'tcp')]}"
        for n in cands
    ]
    udp_ok = sum(1 for n in cands if res[(n, "udp")] == "ok")
    tcp_ok = sum(1 for n in cands if res[(n, "tcp")] == "ok")
    sys_ok = rc == 0 and bool(sysout)
    detail = (
        f"system resolver (getent hosts {ctx.name}): {sysout if sys_ok else 'FAILED - ' + sysout}\n\n"
        + "\n".join(rows)
    )
    data = {
        "system_ok": sys_ok,
        "udp_ok": udp_ok,
        "tcp_ok": tcp_ok,
        "total": len(cands),
        "in_resolv": ns,
    }
    summ = f"system {'OK' if sys_ok else 'FAIL'}; raw udp {udp_ok}/{len(cands)}, tcp {tcp_ok}/{len(cands)}"
    return ("OK" if sys_ok else "FAIL"), summ, detail, data


def check_tcp(ctx):
    def one(t):
        try:
            socket.create_connection(t, timeout=3).close()
            return "ok"
        except socket.timeout:
            return "timeout"
        except ConnectionRefusedError:
            return "refused"
        except OSError as e:
            return e.strerror or type(e).__name__

    with cf.ThreadPoolExecutor(max_workers=len(TCP_TARGETS)) as ex:
        res = list(ex.map(one, TCP_TARGETS))
    rows = [f"{h}:{p:<5} {r}" for (h, p), r in zip(TCP_TARGETS, res)]
    p443 = sum(
        1 for (h, p), r in zip(TCP_TARGETS, res) if p == 443 and r == "ok"
    )
    data = {"p443_ok": p443, "ok": sum(1 for r in res if r == "ok")}
    if p443 == 0:
        return (
            "FAIL",
            "no TCP/443 egress to any test host",
            "\n".join(rows),
            data,
        )
    if data["ok"] < len(res):
        return (
            "WARN",
            f"{data['ok']}/{len(res)} TCP connects ok",
            "\n".join(rows),
            data,
        )
    return (
        "OK",
        f"{len(res)}/{len(res)} TCP connects ok (no DNS needed)",
        "\n".join(rows),
        data,
    )


def check_https(ctx):
    if ctx.offline:
        return "SKIP", "offline mode (no external request)", "", {}
    try:
        req = urllib.request.Request(
            "https://am.i.mullvad.net/json", headers={"User-Agent": "netaudit"}
        )
        j = json.load(urllib.request.urlopen(req, timeout=8))
    except Exception as e:
        return (
            "FAIL",
            f"am.i.mullvad.net unreachable: {type(e).__name__}",
            str(e),
            {},
        )
    keep = {
        k: j.get(k)
        for k in (
            "ip",
            "country",
            "city",
            "mullvad_exit_ip",
            "mullvad_exit_ip_hostname",
            "mullvad_server_type",
            "blacklisted",
        )
    }
    detail = json.dumps(keep, indent=2)
    if j.get("mullvad_exit_ip"):
        return (
            "OK",
            f"on Mullvad: {j.get('mullvad_exit_ip_hostname')} ({j.get('city')})",
            detail,
            keep,
        )
    return (
        "INFO",
        f"not on Mullvad: exit {j.get('ip')} ({j.get('city')})",
        detail,
        keep,
    )


def wg_show(sub):
    rc, out = sh(["wg", "show", WG_IF, sub])
    return out if rc == 0 else None


def check_wireguard(ctx):
    data = {"up": False, "peers": [], "conf": {}, "policy_routing": True}
    rc, link = sh(["ip", "-o", "link", "show", WG_IF])
    data["up"] = rc == 0
    rcr, rules = sh(["ip", "rule", "show"])
    data["policy_routing"] = None if rcr == 127 else rcr == 0
    lines = [
        f"link        : {link if rc == 0 else WG_IF + ' not present'}",
        f"ip rule     : {'supported' if rcr == 0 else ('unknown (ip missing)' if rcr == 127 else 'NOT supported (' + rules[:60] + ') -> wg-quick needs Table = off')}",
    ]
    conf = {}
    if ctx.is_root:
        conf = parse_wg_conf(WG_CONF)
        data["conf"] = {
            k: v for k, v in conf.items() if k not in ("interface",)
        }
        if conf.get("readable"):
            ifc = {
                k: v
                for k, v in conf.get("interface", {}).items()
                if k not in ("postup", "postdown")
            }
            lines += [
                "",
                f"--- {WG_CONF} (mode {conf.get('mode')}; secrets omitted) ---",
                f"own pubkey  : {conf.get('own_pub')}",
                f"peer pubkey : {(conf['peers'][0].get('publickey') if conf['peers'] else None)}",
                f"endpoint    : {conf.get('endpoint_ip')}:{conf.get('endpoint_port')}",
                f"interface   : {json.dumps(ifc)}",
                f"Table=off   : {conf.get('table_off')}   PostUp hooks: {conf.get('has_postup')}",
            ]
        elif conf.get("exists"):
            lines.append(f"{WG_CONF}: not readable")
        else:
            lines.append(f"{WG_CONF}: does not exist")
    status, summ = "INFO", f"{WG_IF} not present"
    if data["up"]:
        if not ctx.is_root:
            status, summ = (
                "WARN",
                f"{WG_IF} up; run with sudo to read handshake state",
            )
        else:

            def pairs(output):
                return [
                    line.split("\t")
                    for line in (output or "").splitlines()
                    if "\t" in line
                ]

            hs = {a: int(b) for a, b in pairs(wg_show("latest-handshakes"))}
            tr = {
                a: (int(b), int(c)) for a, b, c in pairs(wg_show("transfer"))
            }
            ep = dict(pairs(wg_show("endpoints")))
            ai = dict(pairs(wg_show("allowed-ips")))
            data["listen_port"] = wg_show("listen-port")
            now = int(time.time())
            for pk in (wg_show("peers") or "").split():
                e = hs.get(pk, 0)
                rx, tx = tr.get(pk, (0, 0))
                data["peers"].append(
                    {
                        "pub": pk,
                        "endpoint": ep.get(pk),
                        "allowed": ai.get(pk),
                        "hs_age": (now - e) if e else None,
                        "rx": rx,
                        "tx": tx,
                    }
                )
            lines += [
                "",
                f"--- live state ({WG_IF}) ---",
                f"public key  : {wg_show('public-key')}",
                f"listen port : {data['listen_port']}",
            ]
            for p in data["peers"]:
                lines.append(
                    f"peer {p['pub'][:12]}..  endpoint {p['endpoint']}  handshake "
                    f"{'NEVER' if p['hs_age'] is None else str(p['hs_age']) + 's ago'}  rx {p['rx']} B  tx {p['tx']} B"
                )
            eip = conf.get("endpoint_ip")
            if eip:
                rce, er = sh(["ip", "-4", "route", "get", eip])
                data["endpoint_via_wg"] = f"dev {WG_IF}" in er
                lines.append(
                    f"endpoint route: {er.splitlines()[0] if er else '?'}"
                )
            if not data["peers"]:
                status, summ = "FAIL", f"{WG_IF} is up with NO peers loaded"
            elif all(p["hs_age"] is None for p in data["peers"]):
                status, summ = (
                    "FAIL",
                    f"{WG_IF} up, NO handshake (tx {data['peers'][0]['tx']} B / rx {data['peers'][0]['rx']} B)",
                )
            elif any(
                p["hs_age"] is not None and p["hs_age"] > 180
                for p in data["peers"]
            ):
                status, summ = "WARN", "handshake stale (>180 s)"
            else:
                status, summ = (
                    "OK",
                    f"handshake {min(p['hs_age'] for p in data['peers'])}s ago",
                )
            if data.get("endpoint_via_wg"):
                status, summ = (
                    "FAIL",
                    "endpoint routed INTO wg0 (routing loop)",
                )
    if conf.get("peer_is_own_key"):
        status, summ = "FAIL", "wg0.conf peer PublicKey == your own key"
    elif (
        conf.get("readable")
        and not conf.get("table_off")
        and data["policy_routing"] is False
        and status in ("INFO", "OK")
    ):
        status, summ = (
            "WARN",
            "wg0.conf lacks 'Table = off' but kernel has no policy routing",
        )
    return status, summ, "\n".join(lines), data


def check_firewall(ctx):
    if not ctx.is_root:
        return "SKIP", "needs root", "", {}
    rc, nft = sh(["nft", "list", "ruleset"])
    ipt = []
    for tool in ("iptables-legacy-save", "iptables-save", "ip6tables-save"):
        r, o = sh([tool])
        if r == 0:
            ipt.append(
                (
                    tool,
                    [
                        line
                        for line in o.splitlines()
                        if line.startswith("-A ")
                    ],
                )
            )
    block = [
        line.strip()
        for line in (nft if rc == 0 else "").splitlines()
        if re.search(r"\b(drop|reject)\b", line)
        and re.search(r"dport\s*(53|51820|\{)", line)
    ]
    for tool, rules in ipt:
        block += [
            r
            for r in rules
            if re.search(r"-j (DROP|REJECT)", r)
            and re.search(r"dport (53|51820)", r)
        ]
    pol_drop = len(re.findall(r"policy drop", nft)) if rc == 0 else 0
    tables = len(re.findall(r"(?m)^table ", nft)) if rc == 0 else 0
    rules = (
        len(
            [
                line
                for line in nft.splitlines()
                if re.match(r"^\t\t(?!type |policy )\S", line)
            ]
        )
        if rc == 0
        else 0
    )
    detail = (
        (nft if rc == 0 else f"nft: {nft}")
        + "\n\n"
        + "\n".join(f"{t}: {len(r)} rules" for t, r in ipt)
    )
    data = {
        "tables": tables,
        "rules": rules,
        "policy_drop": pol_drop,
        "blocking": block,
    }
    if block:
        return (
            "WARN",
            f"{len(block)} rule(s) drop/reject DNS or WireGuard ports",
            detail + "\n\n" + "\n".join(block),
            data,
        )
    if pol_drop:
        return "WARN", f"{pol_drop} chain(s) with policy drop", detail, data
    return (
        "OK",
        f"nft: {tables} table(s), ~{rules} rules; nothing blocks 53/51820",
        detail,
        data,
    )


def check_listeners(ctx):
    rc, out = sh(["ss", "-tulnp"])
    if rc != 0:
        return "SKIP", "ss unavailable", out, {}
    rows = out.splitlines()[1:]
    ext = [r for r in rows if not re.search(r"\s(127\.|\[::1\]|::1)", r)]
    return (
        "INFO",
        f"{len(rows)} listeners, {len(ext)} not loopback-only",
        out,
        {"total": len(rows), "external": len(ext)},
    )


def check_units(ctx):
    rc, sysu = sh(["systemctl", "--failed", "--no-legend", "--no-pager"])
    usr = ""
    if ctx.is_root and ctx.uid != 0:
        rc2, usr = sh(
            [
                "sudo",
                "-u",
                ctx.user,
                "env",
                f"XDG_RUNTIME_DIR=/run/user/{ctx.uid}",
                "systemctl",
                "--user",
                "--failed",
                "--no-legend",
                "--no-pager",
            ]
        )
        if rc2 != 0:
            usr = ""
    elif not ctx.is_root:
        rc2, usr = sh(
            ["systemctl", "--user", "--failed", "--no-legend", "--no-pager"]
        )
        usr = usr if rc2 == 0 else ""
    failed = [
        line
        for line in (sysu + "\n" + usr).splitlines()
        if line.strip() and "not found" not in line
    ]
    detail = f"--- system ---\n{sysu or '(none)'}\n\n--- user ({ctx.user}) ---\n{usr or '(none)'}"
    if failed:
        return (
            "WARN",
            f"{len(failed)} failed unit(s)",
            detail,
            {"failed": len(failed)},
        )
    return "OK", "no failed units", detail, {"failed": 0}


def check_timeline(ctx):
    rows, notty = [], 0
    rc, out = sh(
        [
            "journalctl",
            "-t",
            "sudo",
            "--since",
            "24 hours ago",
            "-o",
            "short-iso",
            "--no-pager",
        ],
        timeout=15,
    )
    src = out if rc == 0 else ""
    if not src and os.path.exists("/var/log/auth.log"):
        try:
            src = "\n".join(
                line
                for line in open("/var/log/auth.log", errors="replace")
                if "sudo" in line
            )
        except OSError:
            pass
    for line in src.splitlines():
        m = re.match(
            r"^(\S+)\s.*?:\s+(\S+) : TTY=(\S+) ; PWD=.*? ; USER=(\S+) ; COMMAND=(.*)$",
            line,
        )
        if m:
            if m[3] in ("unknown", "?"):
                notty += 1
            rows.append(
                f"{m[1][5:19]}  {m[2]:<10} tty={m[3]:<8} as={m[4]:<5} {m[5][:90]}"
            )
    hist = []
    try:
        t0 = time.time() - 86400
        for line in open(
            os.path.join(ctx.home, ".zsh_history"), errors="replace"
        ):
            m = re.match(r"^: (\d+):\d+;(.*)", line)
            if m and int(m[1]) >= t0 and NETISH.search(m[2]):
                hist.append(
                    f"{time.strftime('%m-%d %H:%M:%S', time.localtime(int(m[1])))}  {m[2][:100]}"
                )
    except OSError:
        pass
    detail = (
        "--- sudo commands, last 24h (tty=pts/N is a terminal; tty=unknown = no terminal) ---\n"
        + (
            "\n".join(rows[-60:])
            or "(none found - journal may be empty or sudo logs elsewhere)"
        )
        + "\n\n--- your zsh history, network-ish, last 24h ---\n"
        + ("\n".join(hist[-60:]) or "(none)")
    )
    return (
        "INFO",
        f"{len(rows)} sudo cmds ({notty} without a tty), {len(hist)} network-ish shell cmds",
        detail,
        {"sudo": len(rows), "notty": notty, "hist": len(hist)},
    )


CHECKS = {
    "system": ("System", check_system),
    "routes": ("Routing", check_routes),
    "gateway": ("Gateway", check_gateway),
    "icmp": ("Internet ping", check_icmp),
    "resolv": ("resolv.conf", check_resolv),
    "dns": ("DNS", check_dns),
    "tcp": ("TCP egress", check_tcp),
    "https": ("Mullvad status", check_https),
    "wireguard": ("WireGuard", check_wireguard),
    "firewall": ("Firewall", check_firewall),
    "listeners": ("Listeners", check_listeners),
    "units": ("Failed units", check_units),
    "timeline": ("Who did what", check_timeline),
}

CHECK_HINTS = {
    "system": "Use this to confirm OS, user identity, and available root access.",
    "routes": "Compare the effective route with the interface you expect to carry traffic.",
    "gateway": "If it fails, verify the eth0 gateway and local network before changing VPN settings.",
    "icmp": "Ping can be filtered; compare with TCP egress before concluding the internet is down.",
    "resolv": "A missing or dangling resolver file can break DNS even when routes are healthy.",
    "dns": "Compare system resolution with raw UDP/TCP results to isolate resolver problems.",
    "tcp": "TCP results distinguish outbound connectivity from DNS or ICMP filtering.",
    "https": "This checks the reported Mullvad exit; offline mode intentionally skips it.",
    "wireguard": "Root access reveals config and handshake evidence; inspect it before repairing.",
    "firewall": "Root access is required; review matching rules before changing firewall policy.",
    "listeners": "Check non-loopback listeners against services you intend to expose.",
    "units": "A failed unit is context, not proof of a network fault; inspect its service first.",
    "timeline": "Journal and shell history can be incomplete; do not treat this as a full audit log.",
}


def diagnose(res):
    def data_for(key):
        return res[key].data if key in res else {}

    r, dn, tc, rs, wg = (
        data_for("routes"),
        data_for("dns"),
        data_for("tcp"),
        data_for("resolv"),
        data_for("wireguard"),
    )
    peers, conf, f = wg.get("peers") or [], wg.get("conf") or {}, []
    if r.get("unreachable"):
        f.append(
            (
                "FAIL",
                "No route to the internet: the eth0 default route is missing.",
                "restore",
            )
        )
    if (
        wg.get("up")
        and peers
        and all(p.get("hs_age") is None for p in peers)
        and r.get("eff_dev") == WG_IF
    ):
        f.append(
            (
                "FAIL",
                "wg0 carries all traffic but never completed a handshake: everything is blackholed.",
                "restore",
            )
        )
    for p in peers:
        if (
            p.get("hs_age") is None
            and p.get("tx", 0) > 0
            and p.get("rx", 0) == 0
        ):
            f.append(
                (
                    "WARN",
                    f"wg0 sent {p['tx']} B, got 0 B back: server not answering. Unregistered device key, "
                    "wrong server key, or UDP/51820 blocked -> use a fresh Mullvad config.",
                    "import",
                )
            )
    if conf.get("peer_is_own_key"):
        f.append(
            (
                "FAIL",
                "wg0.conf [Peer] PublicKey equals your own public key; wireguard-go silently drops it.",
                "import",
            )
        )
    if wg.get("endpoint_via_wg"):
        f.append(
            (
                "FAIL",
                "WireGuard endpoint is routed into wg0 itself (routing loop).",
                "restore",
            )
        )
    if rs.get("state") in ("missing", "dangling", "empty"):
        f.append(
            (
                "FAIL",
                f"/etc/resolv.conf is {rs['state']}: no DNS configured.",
                "restore",
            )
        )
    if (
        dn
        and not dn.get("system_ok")
        and dn.get("udp_ok", 0) == 0
        and tc.get("p443_ok", 0) > 0
        and rs.get("state") == "ok"
    ):
        f.append(
            (
                "WARN",
                "Port 53 is dead to every resolver while 443 works: host DNS proxy hung, upstream filter, or local rule.",
                None,
            )
        )
    if (
        dn
        and not dn.get("system_ok")
        and dn.get("udp_ok", 0) > 0
        and rs.get("state") == "ok"
    ):
        f.append(
            (
                "WARN",
                "Some resolvers answer but the system resolver fails: switch resolv.conf to one that does.",
                "restore",
            )
        )
    if (
        conf.get("readable")
        and not conf.get("table_off")
        and wg.get("policy_routing") is False
    ):
        f.append(
            (
                "WARN",
                "wg0.conf lacks 'Table = off' but this kernel has no policy routing: wg-quick up will fail.",
                "import",
            )
        )
    if data_for("firewall").get("blocking"):
        f.append(
            (
                "WARN",
                "A firewall rule drops DNS or WireGuard ports (see Firewall).",
                None,
            )
        )
    if data_for("units").get("failed"):
        f.append(
            (
                "WARN",
                f"{data_for('units')['failed']} failed systemd unit(s) (see Failed units).",
                None,
            )
        )
    return sorted(f, key=lambda x: -SEV[x[0]])


# ----------------------------------------------------------------------------- audit runner
class Audit:
    def __init__(self, ctx):
        self.ctx, self.results, self.lock, self.active = (
            ctx,
            {},
            threading.Lock(),
            0,
        )

    def _one(self, cid):
        title, fn = CHECKS[cid]
        t0 = time.time()
        try:
            st, sm, de, da = fn(self.ctx)
        except Exception as e:
            st, sm, de, da = (
                "WARN",
                f"check crashed: {type(e).__name__}: {e}",
                traceback.format_exc(),
                {},
            )
        with self.lock:
            self.results[cid] = Result(
                cid, title, st, sm, de, da, time.time() - t0
            )
            self.active -= 1

    def start(self, ids=None):
        ids = ids or list(CHECKS)
        with self.lock:
            for i in ids:
                self.results.pop(i, None)
            self.active += len(ids)
        for i in ids:
            threading.Thread(target=self._one, args=(i,), daemon=True).start()

    def wait(self):
        while self.active:
            time.sleep(0.1)

    def report(self):
        ctx = self.ctx
        checks = [
            dataclasses.asdict(self.results[i])
            for i in CHECKS
            if i in self.results
        ]
        diag = [
            {"severity": s, "finding": t, "action": a}
            for s, t, a in diagnose(self.results)
        ]
        rep = {
            "tool": f"netaudit {VERSION}",
            "generated": dt.datetime.now()
            .astimezone()
            .isoformat(timespec="seconds"),
            "host": socket.gethostname(),
            "user": ctx.user,
            "root": ctx.is_root,
            "offline": ctx.offline,
            "redacted": ctx.redact_on,
            "diagnosis": diag,
            "checks": checks,
        }
        return redact_obj(rep) if ctx.redact_on else rep


# ----------------------------------------------------------------------------- exporters
def fmt_json(rep):
    return json.dumps(rep, indent=2, default=str)


def fmt_txt(rep):
    o = [
        f"{rep['tool']} report  {rep['generated']}  host={rep['host']} user={rep['user']} root={rep['root']} "
        f"redacted={rep['redacted']}",
        "",
        "DIAGNOSIS",
    ]
    o += [f"  [{d['severity']}] {d['finding']}" for d in rep["diagnosis"]] or [
        "  no problems detected"
    ]
    o += ["", "CHECKS"] + [
        f"  [{c['status']:<4}] {c['title']:<16} {c['summary']}"
        for c in rep["checks"]
    ]
    for c in rep["checks"]:
        o += [
            "",
            "=" * 70,
            f"{c['title']}  [{c['status']}]",
            "=" * 70,
            c["detail"] or "(no detail)",
        ]
    return "\n".join(o) + "\n"


def fmt_md(rep):
    o = [
        "# netaudit report",
        f"`{rep['generated']}` host `{rep['host']}` user `{rep['user']}` root `{rep['root']}` "
        f"redacted `{rep['redacted']}`",
        "",
        "## Diagnosis",
    ]
    o += [
        f"- **{d['severity']}** {d['finding']}" for d in rep["diagnosis"]
    ] or ["- no problems detected"]
    o += ["", "## Checks", "| status | check | summary |", "|---|---|---|"]
    o += [
        f"| {c['status']} | {c['title']} | {c['summary'].replace('|', '/')} |"
        for c in rep["checks"]
    ]
    for c in rep["checks"]:
        o += [
            "",
            f"### {c['title']} ({c['status']})",
            "```",
            c["detail"] or "(no detail)",
            "```",
        ]
    return "\n".join(o) + "\n"


def fmt_html(rep):
    col = {
        "OK": "#2a7",
        "WARN": "#c90",
        "FAIL": "#d33",
        "INFO": "#38a",
        "SKIP": "#888",
    }
    e = html.escape
    o = [
        "<!doctype html><meta charset=utf-8><title>netaudit</title><style>body{font:14px monospace;margin:1.5em}"
        "pre{background:#f4f4f4;padding:.6em;overflow:auto}</style>",
        f"<h1>netaudit</h1><p>{e(rep['generated'])} "
        f"host {e(rep['host'])} user {e(rep['user'])} redacted {rep['redacted']}</p><h2>Diagnosis</h2><ul>",
    ]
    o += [
        f"<li style='color:{col[d['severity']]}'><b>{d['severity']}</b> {e(d['finding'])}</li>"
        for d in rep["diagnosis"]
    ] or ["<li>no problems detected</li>"]
    o += ["</ul><h2>Checks</h2><table border=1 cellpadding=4 cellspacing=0>"]
    o += [
        f"<tr><td style='color:{col[c['status']]}'><b>{c['status']}</b></td><td>{e(c['title'])}</td>"
        f"<td>{e(c['summary'])}</td></tr>"
        for c in rep["checks"]
    ]
    o += ["</table>"] + [
        f"<h3>{e(c['title'])} ({c['status']})</h3><pre>{e(c['detail'])}</pre>"
        for c in rep["checks"]
    ]
    return "\n".join(o) + "\n"


def fmt_csv(rep):
    b = io.StringIO()
    w = csv.writer(b)
    w.writerow(["id", "title", "status", "summary", "seconds"])
    for c in rep["checks"]:
        w.writerow(
            [
                c["id"],
                c["title"],
                c["status"],
                c["summary"],
                round(c["secs"], 2),
            ]
        )
    return b.getvalue()


FORMATS = {
    "json": ("report.json", fmt_json),
    "md": ("report.md", fmt_md),
    "txt": ("report.txt", fmt_txt),
    "html": ("report.html", fmt_html),
    "csv": ("checks.csv", fmt_csv),
}


def expand_format_patterns(patterns):
    available = [*FORMATS, "bundle"]
    selected = []
    unmatched = []
    for pattern in patterns:
        matches = [
            name for name in available if fnmatch.fnmatchcase(name, pattern)
        ]
        if not matches:
            unmatched.append(pattern)
        for name in matches:
            if name not in selected:
                selected.append(name)
    return selected, unmatched


def export(rep, fmts, ctx, outdir=None):
    base = outdir or os.path.join(
        ctx.home, "netaudit_reports", time.strftime("%Y%m%d_%H%M%S")
    )
    os.makedirs(base, mode=0o700, exist_ok=True)
    written = []

    def put(name, data):
        p = os.path.join(base, name)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
        written.append(p)

    for f in fmts:
        if f in FORMATS:
            put(FORMATS[f][0], FORMATS[f][1](rep))
    if "bundle" in fmts:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:

            def add(name, data):
                ti = tarfile.TarInfo(name)
                ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
                tf.addfile(ti, io.BytesIO(data))

            for name, fn in FORMATS.values():
                add(f"netaudit/{name}", fn(rep).encode())
            for c in rep["checks"]:
                add(
                    f"netaudit/raw/{c['id']}.txt", (c["detail"] or "").encode()
                )
        put("bundle.tar.gz", buf.getvalue())
    lines = []
    for fn in sorted(os.listdir(base)):
        if fn != "MANIFEST.sha256":
            lines.append(
                f"{hashlib.sha256(open(os.path.join(base, fn), 'rb').read()).hexdigest()}  {fn}"
            )
    put("MANIFEST.sha256", "\n".join(lines) + "\n")
    if ctx.is_root and ctx.uid != 0:
        for p in [base] + written:
            try:
                os.chown(p, ctx.uid, ctx.gid)
            except OSError:
                pass
        parent = os.path.dirname(base)
        if os.path.basename(parent) == "netaudit_reports":
            try:
                os.chown(parent, ctx.uid, ctx.gid)
            except OSError:
                pass
    return written


# ----------------------------------------------------------------------------- repairs (only via explicit confirm)
def log_action(ctx, text):
    try:
        d = os.path.join(ctx.home, "netaudit_reports")
        os.makedirs(d, mode=0o700, exist_ok=True)
        with open(os.path.join(d, "actions.log"), "a") as fh:
            fh.write(
                f"{dt.datetime.now().astimezone().isoformat(timespec='seconds')} {redact(text)}\n"
            )
        if ctx.is_root and ctx.uid != 0:
            os.chown(d, ctx.uid, ctx.gid)
            os.chown(os.path.join(d, "actions.log"), ctx.uid, ctx.gid)
    except OSError:
        pass


def write_file(path, content, mode):
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    os.replace(
        tmp, path
    )  # replaces a dangling/valid symlink itself, never follows it


def plan_restore(ctx):
    steps = []
    if sh(["ip", "-o", "link", "show", WG_IF])[0] == 0:
        steps.append(
            (
                "tear down wg0",
                [
                    "sh",
                    "-c",
                    f"wg-quick down {WG_IF} 2>/dev/null || ip link delete dev {WG_IF}",
                ],
            )
        )
    ep = parse_wg_conf(WG_CONF).get("endpoint_ip")
    if ep:
        steps.append(
            (
                f"remove endpoint pin {ep}/32",
                ["sh", "-c", f"ip route del {ep}/32 2>/dev/null; true"],
            )
        )
    gw = ctx.gateway()
    steps.append(
        (
            f"default route via {gw} dev eth0",
            ["ip", "route", "replace", "default", "via", gw, "dev", "eth0"],
        )
    )
    if resolv_state()[0] != "ok":
        steps.append(
            (
                "write /etc/resolv.conf (nameserver 1.1.1.1)",
                ("write", "/etc/resolv.conf", "nameserver 1.1.1.1\n", 0o644),
            )
        )
    steps.append(
        (f"verify: getent hosts {ctx.name}", ["getent", "hosts", ctx.name])
    )
    return steps


def run_steps(ctx, steps):
    out = []
    for label, st in steps:
        if isinstance(st, tuple):
            try:
                write_file(st[1], st[2], st[3])
                rc, o = 0, f"wrote {st[1]}"
            except OSError as e:
                rc, o = 1, str(e)
        else:
            rc, o = sh(st, timeout=20)
        out.append(
            f"[{'ok' if rc == 0 else 'error'}] {label}"
            + (f"\n      {o[:200]}" if o else "")
        )
    log_action(
        ctx,
        "ACTION " + " | ".join(step.splitlines()[0] for step in out),
    )
    return out


def action_wg_up(ctx):
    log = []
    c = parse_wg_conf(WG_CONF)
    problems = []
    if not c.get("exists"):
        problems.append(f"{WG_CONF} does not exist")
    elif not c.get("readable"):
        problems.append("config not readable")
    else:
        if c.get("peer_is_own_key"):
            problems.append(
                "peer PublicKey equals your own key -> Import Mullvad config"
            )
        if not c.get("endpoint_ip"):
            problems.append("Endpoint must be an IPv4:port literal")
        if sh(["ip", "rule", "show"])[0] not in (0, 127) and not (
            c.get("table_off") and c.get("has_postup")
        ):
            problems.append(
                "no policy routing and no 'Table = off' + PostUp hooks -> Import Mullvad config"
            )
    if problems:
        return ["[error] preflight: " + p for p in problems]
    if resolv_state()[0] != "ok":
        log += run_steps(
            ctx,
            [
                (
                    "write /etc/resolv.conf",
                    (
                        "write",
                        "/etc/resolv.conf",
                        "nameserver 1.1.1.1\n",
                        0o644,
                    ),
                )
            ],
        )
    sh(["wg-quick", "down", WG_IF])
    rc, o = sh(["wg-quick", "up", WG_IF], timeout=25)
    log.append(
        f"[{'ok' if rc == 0 else 'error'}] wg-quick up {WG_IF}\n      {o[-300:]}"
    )
    ok = False
    if rc == 0:
        for _ in range(10):
            sh(["ping", "-c", "1", "-W", "1", "1.1.1.1"])
            hs = (wg_show("latest-handshakes") or "").split()
            if hs and hs[-1].isdigit() and int(hs[-1]) > 0:
                ok = True
                break
            time.sleep(0.5)
    if ok:
        log.append("[ok] handshake completed: tunnel is carrying traffic")
    else:
        log.append(
            "[error] no handshake within ~10 s: REVERTING to direct internet"
        )
        log += run_steps(ctx, plan_restore(ctx))
    log_action(ctx, "ACTION wg-up " + ("ok" if ok else "reverted"))
    return log


def action_import(ctx, src):
    src = os.path.expanduser(src.strip())
    c = parse_wg_conf(src)
    errs = []
    if not c.get("readable"):
        errs.append(f"cannot read {src}")
    else:
        if not c.get("has_privatekey"):
            errs.append("no PrivateKey in file")
        if not c["interface"].get("address"):
            errs.append("no Address in [Interface]")
        if len(c["peers"]) != 1 or not c["peers"][0].get("publickey"):
            errs.append("expected exactly one [Peer] with PublicKey")
        if not c.get("endpoint_ip"):
            errs.append(
                "Endpoint must be an IPv4:port literal (Mullvad configs are)"
            )
        if c.get("peer_is_own_key"):
            errs.append(
                "peer PublicKey equals your own key: this config is also broken"
            )
    if errs:
        return ["[error] " + e for e in errs]
    ep, gw = c["endpoint_ip"], ctx.gateway()
    hooks = [
        "Table = off",
        f"PostUp = ip route replace {ep}/32 via {gw} dev eth0; ip route replace 0.0.0.0/1 dev {WG_IF}; "
        f"ip route replace 128.0.0.0/1 dev {WG_IF}",
        f"PostDown = ip route del {ep}/32 || true; ip route del 0.0.0.0/1 || true; ip route del 128.0.0.0/1 || true; "
        f'[ -s /etc/resolv.conf ] || echo "nameserver 1.1.1.1" > /etc/resolv.conf',
    ]
    out, sec = [], ""
    for raw in open(src).read().splitlines():
        s = re.sub(r"\s", "", raw).lower()
        if s.startswith("["):
            sec = s
            out.append(raw)
            if s == "[interface]":
                out += hooks
            continue
        if sec == "[interface]" and re.match(r"(table|postup|postdown)=", s):
            continue
        out.append(raw)
    log = []
    os.makedirs("/etc/wireguard", mode=0o700, exist_ok=True)
    if os.path.exists(WG_CONF):
        bak = f"{WG_CONF}.bak.{int(time.time())}"
        shutil.copy2(WG_CONF, bak)
        log.append(f"[ok] backed up old config -> {bak}")
    write_file(WG_CONF, "\n".join(out) + "\n", 0o600)
    log.append(
        f"[ok] installed {WG_CONF} (0600): peer {c['peers'][0]['publickey'][:10]}.. endpoint {ep}, "
        f"Table=off, route hooks via {gw}"
    )
    log.append(
        "[ok] next: Actions > 'Bring tunnel UP (auto-revert)'. The downloaded file still holds your private key: delete it."
    )
    log_action(ctx, f"ACTION import-conf from {src}")
    return log


# ----------------------------------------------------------------------------- TUI
HELP = """QUICK START
    1. Wait for the checks to finish; results appear as they complete.
    2. Select a check and press Enter for its evidence. Press d for diagnosis.
    3. Press e to export. Toggle formats, choose a folder, then press Enter.
    4. Use a repair action only when you understand the confirmation steps.

MAIN KEYS
    up/down j/k   select check          Enter  show full detail
    r  re-run all   R  re-run selected   d  full diagnosis
    e  export menu  a  repair actions    t  toggle report redaction
    ?  this help    q  quit
DETAIL / DIAGNOSIS: j/k PgUp/PgDn scroll, q/Esc/Enter back
EXPORT: j/m/t/h/c/b toggle formats; a or * select all; n clear; o choose folder
    Enter writes selected formats; leave folder blank for the default; q/Esc back.
CLI FORMAT WILDCARDS: --export 'j*,bundle' selects JSON and the bundle.
FORMATS: JSON, Markdown, plain text, HTML, CSV, and a tar.gz bundle.
Reports use mode 0600 and include a SHA-256 manifest. Redaction is on by default.
Repairs never run on their own: each shows the exact steps and needs 'y'."""


class App:
    def __init__(self, scr, ctx, audit):
        self.scr, self.ctx, self.audit = scr, ctx, audit
        self.sel = self.top = self.scroll = 0
        self.mode, self.title, self.body, self.msg = "main", "", [], ""
        self.outdir = ""
        self.fmt = {
            "json": True,
            "md": True,
            "txt": False,
            "html": False,
            "csv": False,
            "bundle": True,
        }
        self.asel = 0
        self.actions = [
            (
                "restore",
                "Restore direct internet (tear down wg0, default route, resolv.conf)",
            ),
            ("wgup", "Bring tunnel UP with auto-revert if no handshake"),
            (
                "import",
                "Import a Mullvad .conf (adds Table=off + route hooks, backs up old)",
            ),
        ]
        curses.curs_set(0) if hasattr(curses, "curs_set") else None
        scr.keypad(True)
        scr.timeout(150)
        self.c = {k: 0 for k in ("OK", "WARN", "FAIL", "INFO", "SKIP", "HDR")}
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
                bg = -1
            except curses.error:
                bg = 0
            for i, (k, fg) in enumerate(
                [
                    ("OK", curses.COLOR_GREEN),
                    ("WARN", curses.COLOR_YELLOW),
                    ("FAIL", curses.COLOR_RED),
                    ("INFO", curses.COLOR_CYAN),
                    ("SKIP", curses.COLOR_WHITE),
                ],
                1,
            ):
                curses.init_pair(i, fg, bg)
                self.c[k] = curses.color_pair(i) | (
                    curses.A_DIM if k == "SKIP" else 0
                )
        self.c["HDR"] = curses.A_REVERSE

    def put(self, y, x, s, attr=0):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w - 1:
            try:
                self.scr.addstr(y, x, s[: w - x - 1], attr)
            except curses.error:
                pass

    def wrap(self, text, w):
        out = []
        for line in text.splitlines() or [""]:
            line = line.expandtabs(4)
            out += [line[i : i + w] for i in range(0, max(len(line), 1), w)]
        return out

    def main_hint(self):
        if self.audit.active:
            return (
                f"{len(self.audit.results)}/{len(CHECKS)} checks finished. Results update as checks "
                "complete; no repairs run automatically."
            )
        ids = list(CHECKS)
        cid = ids[self.sel]
        result = self.audit.results.get(cid)
        if not result:
            return (
                f"{CHECKS[cid][0]} has not run yet. Press r to run the audit."
            )
        hint = CHECK_HINTS[cid]
        if result.status in ("FAIL", "WARN"):
            return f"{result.status}: {hint} Next: Enter for evidence or d for diagnosis."
        if result.status == "SKIP":
            return f"Skipped: {hint} Check root access or whether the required command is installed."
        return f"{CHECKS[cid][0]}: {hint} Press Enter to inspect its evidence."

    def export_hint(self):
        selected = [fmt for fmt, enabled in self.fmt.items() if enabled]
        if not selected:
            return "Select at least one format. Press a to select all or n to clear the selection."
        if "bundle" in selected and not self.ctx.redact_on:
            return "Caution: bundle includes detailed check output and redaction is OFF; review before sharing."
        if "bundle" in selected:
            return "Bundle includes detailed per-check output. Redaction is ON; still review before sharing."
        return f"{len(selected)} format(s) selected. Use o to choose a folder; blank keeps the default."

    def view(self, title, text):
        self.mode, self.title, self.body, self.scroll = "view", title, text, 0

    def draw_view(self):
        h, w = self.scr.getmaxyx()
        lines = self.wrap(self.body, max(w - 2, 20))
        self.scroll = max(0, min(self.scroll, max(0, len(lines) - (h - 2))))
        self.put(0, 0, f" {self.title} ".ljust(w), self.c["HDR"])
        for i, l in enumerate(lines[self.scroll : self.scroll + h - 2]):
            self.put(1 + i, 1, l)
        self.put(
            h - 1,
            0,
            f" j/k PgUp/PgDn scroll  q back   {self.scroll + 1}/{max(1, len(lines))} ".ljust(
                w
            ),
            self.c["HDR"],
        )

    def draw_main(self):
        h, w = self.scr.getmaxyx()
        a, ctx = self.audit, self.ctx
        done, total = len(a.results), len(CHECKS)
        hdr = (
            f" netaudit {VERSION}  {'ROOT' if ctx.is_root else 'non-root (limited)'}  redact:{'ON' if ctx.redact_on else 'OFF'}"
            f"  offline:{'Y' if ctx.offline else 'N'}  {done}/{total} {'RUNNING' if a.active else 'done'} "
        )
        self.put(0, 0, hdr.ljust(w), self.c["HDR"])
        y = 1
        if a.active:
            self.put(y, 1, "auditing...", self.c["INFO"])
            y += 1
        else:
            diag = diagnose(a.results)
            if not diag:
                self.put(y, 1, "OK   no problems detected", self.c["OK"])
                y += 1
            for sev, txt, act in diag[:3]:
                self.put(y, 1, f"{sev:<4} {txt}", self.c[sev])
                y += 1
            if len(diag) > 3:
                self.put(
                    y, 1, f"...{len(diag) - 3} more (press d)", self.c["INFO"]
                )
                y += 1
        y += 1
        vis = max(1, h - y - 3)
        ids = list(CHECKS)
        self.sel = max(0, min(self.sel, len(ids) - 1))
        self.top = (
            min(max(self.top, self.sel - vis + 1), self.sel)
            if self.sel < self.top or self.sel >= self.top + vis
            else self.top
        )
        for row, cid in enumerate(ids[self.top : self.top + vis]):
            r = a.results.get(cid)
            sel = (self.top + row) == self.sel
            st = r.status if r else "...."
            line = f" {CHECKS[cid][0]:<15} {r.summary if r else 'running'}"
            attr = self.c.get(st, 0)
            self.put(
                y + row,
                0,
                f"[{st:<4}]",
                attr | (curses.A_REVERSE if sel else 0),
            )
            self.put(
                y + row, 6, line.ljust(w - 7), curses.A_REVERSE if sel else 0
            )
        keys = " Enter detail  r rerun  e export  a repair  d diagnosis  t redact  ? help  q quit "
        self.put(
            h - 2,
            0,
            (" Hint: " + self.main_hint())[: max(0, w - 1)],
            self.c["INFO"],
        )
        self.put(h - 1, 0, (self.msg or keys).ljust(w), self.c["HDR"])

    def draw_export(self):
        h, w = self.scr.getmaxyx()
        self.put(
            0,
            0,
            " Export (redaction %s) "
            % ("ON" if self.ctx.redact_on else "OFF"),
            self.c["HDR"],
        )
        names = {
            "json": "j  JSON (machine-readable)",
            "md": "m  Markdown report",
            "txt": "t  Plain text report",
            "html": "h  HTML report",
            "csv": "c  CSV (check table)",
            "bundle": "b  tar.gz bundle (all formats + raw per-check output)",
        }
        self.put(1, 2, "Choose formats, then press Enter to write:")
        for i, k in enumerate(names):
            self.put(2 + i, 2, f"[{'x' if self.fmt[k] else ' '}] {names[k]}")
        destination = (
            self.outdir or "~/netaudit_reports/<timestamp>/ (default)"
        )
        self.put(9, 2, f"Folder: {destination}")
        self.put(
            10,
            2,
            "a or * select all   n clear all   o choose folder   Esc back",
        )
        self.put(
            h - 2,
            0,
            (self.msg or self.export_hint())[: max(0, w - 1)],
            self.c["INFO"],
        )
        self.put(
            h - 1,
            0,
            " j/m/t/h/c/b toggle format   Enter write ".ljust(w),
            self.c["HDR"],
        )

    def draw_actions(self):
        h, w = self.scr.getmaxyx()
        self.put(
            0,
            0,
            " Repair actions (each asks for confirmation) ",
            self.c["HDR"],
        )
        if self.ctx.readonly:
            self.put(2, 2, "--readonly: repairs disabled", self.c["WARN"])
        elif not self.ctx.is_root:
            self.put(
                2, 2, "needs root: quit and run: sudo netaudit", self.c["WARN"]
            )
        hints = {
            "restore": "Restores direct routing and DNS; use if the tunnel is blocking connectivity.",
            "wgup": "Starts the configured tunnel; if no handshake arrives, direct routing is restored.",
            "import": "Validates and backs up config, then adds full-tunnel routes; source still has its key.",
        }
        self.put(3, 2, hints[self.actions[self.asel][0]])
        for i, (k, d) in enumerate(self.actions):
            self.put(
                4 + i,
                2,
                ("> " if i == self.asel else "  ") + d,
                curses.A_REVERSE if i == self.asel else 0,
            )
        self.put(
            h - 1,
            0,
            " up/down select, Enter run (with confirm), Esc back ".ljust(w),
            self.c["HDR"],
        )

    def prompt(self, label):
        h, w = self.scr.getmaxyx()
        if h < 2 or w < 4:
            return ""
        start = min(len(label) + 3, w - 2)
        self.put(h - 1, 0, f" {label}: ".ljust(w - 1), self.c["HDR"])
        self.scr.refresh()
        try:
            curses.echo()
            try:
                curses.curs_set(1)
            except curses.error:
                pass
            self.scr.timeout(-1)
            return (
                self.scr.getstr(h - 1, start, max(1, min(300, w - start - 1)))
                .decode(errors="replace")
                .strip()
            )
        except curses.error:
            return ""
        finally:
            curses.noecho()
            self.scr.timeout(150)
            try:
                curses.curs_set(0)
            except curses.error:
                pass

    def confirm(self, title, lines):
        self.scr.erase()
        self.put(
            0,
            0,
            f" CONFIRM: {title} ".ljust(self.scr.getmaxyx()[1]),
            self.c["FAIL"] | curses.A_REVERSE,
        )
        for i, l in enumerate(lines):
            self.put(2 + i, 2, l)
        self.put(
            3 + len(lines), 2, "Proceed? press y to run, anything else cancels"
        )
        self.scr.refresh()
        self.scr.timeout(-1)
        k = self.scr.getch()
        self.scr.timeout(150)
        return k in (ord("y"), ord("Y"))

    def do_action(self):
        key = self.actions[self.asel][0]
        if self.ctx.readonly or not self.ctx.is_root:
            self.msg = "repairs need root and no --readonly"
            return
        if key == "restore":
            steps = plan_restore(self.ctx)
            if self.confirm(
                "restore direct internet",
                [f"{i + 1}. {l}" for i, (l, _) in enumerate(steps)],
            ):
                self.view(
                    "Restore: result", "\n".join(run_steps(self.ctx, steps))
                )
                self.audit.start()
        elif key == "wgup":
            if self.confirm(
                "bring wg0 up",
                [
                    "wg-quick down/up wg0, wait ~10 s for a handshake",
                    "if no handshake: automatically run the restore steps",
                ],
            ):
                self.scr.erase()
                self.put(1, 2, "working (up to ~25 s)...")
                self.scr.refresh()
                self.view(
                    "Tunnel up: result", "\n".join(action_wg_up(self.ctx))
                )
                self.audit.start()
        elif key == "import":
            src = self.prompt("path to Mullvad .conf")
            if src and self.confirm(
                "install WireGuard config",
                [
                    f"read {src}",
                    f"back up + replace {WG_CONF} (0600)",
                    "add Table=off + PostUp/PostDown route hooks",
                ],
            ):
                self.view(
                    "Import: result", "\n".join(action_import(self.ctx, src))
                )

    def loop(self):
        while True:
            self.scr.erase()
            {
                "main": self.draw_main,
                "view": self.draw_view,
                "export": self.draw_export,
                "actions": self.draw_actions,
            }[self.mode]()
            self.scr.refresh()
            k = self.scr.getch()
            if k in (-1, curses.KEY_RESIZE):
                continue
            self.msg = "" if self.mode != "export" else self.msg
            if self.mode == "view":
                if k in (ord("q"), 27, 10, curses.KEY_ENTER):
                    self.mode = "main"
                elif k in (curses.KEY_DOWN, ord("j")):
                    self.scroll += 1
                elif k in (curses.KEY_UP, ord("k")):
                    self.scroll -= 1
                elif k == curses.KEY_NPAGE:
                    self.scroll += 15
                elif k == curses.KEY_PPAGE:
                    self.scroll -= 15
            elif self.mode == "export":
                ch = chr(k) if 0 <= k < 256 else ""
                keymap = {
                    "j": "json",
                    "m": "md",
                    "t": "txt",
                    "h": "html",
                    "c": "csv",
                    "b": "bundle",
                }
                if ch in keymap:
                    self.fmt[keymap[ch]] = not self.fmt[keymap[ch]]
                elif ch == "a":
                    self.fmt = {fmt: True for fmt in self.fmt}
                elif ch == "*":
                    self.fmt = {fmt: True for fmt in self.fmt}
                elif ch == "n":
                    self.fmt = {fmt: False for fmt in self.fmt}
                elif ch == "o":
                    self.outdir = os.path.expanduser(
                        self.prompt("export folder (blank for default)")
                    )
                elif k in (27, ord("q")):
                    self.mode = "main"
                elif k in (10, curses.KEY_ENTER):
                    fm = [f for f, on in self.fmt.items() if on]
                    if not fm:
                        self.msg = "select at least one format"
                    elif self.audit.active:
                        self.msg = "audit still running, wait a moment"
                    else:
                        try:
                            paths = export(
                                self.audit.report(),
                                fm,
                                self.ctx,
                                self.outdir or None,
                            )
                            self.msg = "wrote %d files to %s" % (
                                len(paths),
                                os.path.dirname(paths[0]),
                            )
                        except Exception as e:
                            self.msg = f"export failed: {e}"
            elif self.mode == "actions":
                if k in (27, ord("q")):
                    self.mode = "main"
                elif k in (curses.KEY_DOWN, ord("j")):
                    self.asel = (self.asel + 1) % len(self.actions)
                elif k in (curses.KEY_UP, ord("k")):
                    self.asel = (self.asel - 1) % len(self.actions)
                elif k in (10, curses.KEY_ENTER):
                    self.do_action()
            else:
                n = len(CHECKS)
                if k in (ord("q"), 27):
                    return
                elif k in (curses.KEY_DOWN, ord("j")):
                    self.sel = min(self.sel + 1, n - 1)
                elif k in (curses.KEY_UP, ord("k")):
                    self.sel = max(self.sel - 1, 0)
                elif k == curses.KEY_NPAGE:
                    self.sel = min(self.sel + 8, n - 1)
                elif k == curses.KEY_PPAGE:
                    self.sel = max(self.sel - 8, 0)
                elif k in (10, curses.KEY_ENTER):
                    cid = list(CHECKS)[self.sel]
                    r = self.audit.results.get(cid)
                    self.view(
                        f"{CHECKS[cid][0]} [{r.status if r else 'running'}]  {r.summary if r else ''}",
                        (
                            redact(r.detail)
                            if (r and self.ctx.redact_on)
                            else (r.detail if r else "still running...")
                        ),
                    )
                elif k == ord("r") and not self.audit.active:
                    self.audit.start()
                elif k == ord("R") and not self.audit.active:
                    self.audit.start([list(CHECKS)[self.sel]])
                elif k == ord("d"):
                    d = diagnose(self.audit.results)
                    self.view(
                        "Diagnosis",
                        "\n\n".join(
                            f"[{s}] {t}"
                            + (f"\n    fix: Actions > {act}" if act else "")
                            for s, t, act in d
                        )
                        or "no problems detected",
                    )
                elif k == ord("e"):
                    self.mode = "export"
                elif k == ord("a"):
                    self.mode = "actions"
                elif k == ord("t"):
                    self.ctx.redact_on = not self.ctx.redact_on
                    self.msg = (
                        "redaction %s (applies to exports/detail now)"
                        % ("ON" if self.ctx.redact_on else "OFF")
                    )
                elif k == ord("?"):
                    self.view("Help", HELP)


def run_tui(ctx):
    audit = Audit(ctx)
    audit.start()

    def _main(scr):
        App(scr, ctx, audit).loop()

    curses.wrapper(_main)


# ----------------------------------------------------------------------------- selftest
def selftest():
    ok = fail = 0

    def t(name, cond):
        nonlocal ok, fail
        print(f"[{'ok' if cond else 'error'}] {name}")
        ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)

    t(
        "redact PrivateKey",
        "SECRET"
        not in redact("PrivateKey = SECRETSECRET=\nPublicKey = pubpubpub=")
        and "pubpubpub" in redact("PublicKey = pubpubpub="),
    )
    t("redact token", "ghp_" not in redact("x ghp_" + "a" * 30))
    t(
        "parse_ping",
        parse_ping(
            "2 packets transmitted, 2 received, 0% packet loss, time 1ms\nrtt min/avg/max/mdev = 1.0/2.5/4.0/1.0 ms"
        )
        == {"tx": 2, "rx": 2, "loss": 0.0, "avg": 2.5},
    )
    t("every check has an inline hint", set(CHECK_HINTS) == set(CHECKS))
    t(
        "format wildcard selects matching formats",
        expand_format_patterns(["j*", "bundle"]) == (["json", "bundle"], []),
    )
    t(
        "format wildcard selects all formats once",
        expand_format_patterns(["*", "json"]) == ([*FORMATS, "bundle"], []),
    )
    t(
        "unmatched format wildcard is reported",
        expand_format_patterns(["no-such-format*"])
        == ([], ["no-such-format*"]),
    )

    class ChunkedSocket:
        def __init__(self, chunks):
            self.chunks = iter(chunks)

        def recv(self, size):
            return next(self.chunks, b"")[:size]

    t(
        "recv_exact handles partial reads",
        recv_exact(ChunkedSocket([b"\x00", b"\x03"]), 2) == b"\x00\x03",
    )
    try:
        recv_exact(ChunkedSocket([b"\x00"]), 2)
        complete = True
    except ConnectionError:
        complete = False
    t("recv_exact detects truncated streams", not complete)
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def _serve():
        q, a = srv.recvfrom(512)
        srv.sendto(
            q[:2]
            + b"\x81\x80"
            + q[4:6]
            + b"\x00\x01\x00\x00\x00\x00"
            + q[12:]
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04",
            a,
        )

    threading.Thread(target=_serve, daemon=True).start()
    t(
        "dns_query parses a real UDP answer",
        dns_query("127.0.0.1", "example.com", "udp", 2, srv.getsockname()[1])
        == "ok",
    )
    srv.close()
    t(
        "dns_query reports timeout/refused as a name",
        dns_query("127.0.0.1", "example.com", "tcp", 0.5, 9)
        in ("refused", "timeout"),
    )
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "w.conf")
        open(p, "w").write(
            "[Interface]\nPrivateKey = SECRETKEY\nAddress = 10.1.2.3/32\nTable = off\nPostUp = true\n"
            "[Peer]\nPublicKey = peerpub\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n"
        )
        c = parse_wg_conf(p)
        t(
            "conf parsed, endpoint ip",
            c["endpoint_ip"] == "203.0.113.9"
            and c["table_off"]
            and c["has_postup"],
        )
        t("conf never stores private key", "SECRETKEY" not in json.dumps(c))
        ctx = Ctx(offline=True)
        res = {
            "routes": Result(
                "routes",
                "r",
                "INFO",
                "",
                "",
                {"eff_dev": "wg0", "unreachable": False},
            ),
            "wireguard": Result(
                "wireguard",
                "w",
                "FAIL",
                "",
                "",
                {
                    "up": True,
                    "peers": [{"hs_age": None, "tx": 296, "rx": 0}],
                    "conf": {"peer_is_own_key": True},
                },
            ),
        }
        d = diagnose(res)
        t(
            "diagnose blackhole + own-key + unregistered-key",
            len(d) >= 3 and d[0][0] == "FAIL",
        )
        rep = {
            "tool": "t",
            "generated": "now",
            "host": "h",
            "user": "u",
            "root": False,
            "offline": True,
            "redacted": True,
            "diagnosis": [
                {"severity": "FAIL", "finding": "x|y", "action": None}
            ],
            "checks": [
                {
                    "id": "a",
                    "title": "A",
                    "status": "OK",
                    "summary": "s",
                    "detail": "d",
                    "data": {},
                    "secs": 0.1,
                }
            ],
        }
        w = export(
            rep,
            ["json", "md", "txt", "html", "csv", "bundle"],
            ctx,
            os.path.join(td, "out"),
        )
        names = sorted(os.path.basename(x) for x in w)
        t(
            "export writes all formats + manifest",
            {
                "report.json",
                "report.md",
                "report.txt",
                "report.html",
                "checks.csv",
                "bundle.tar.gz",
                "MANIFEST.sha256",
            }
            <= set(names),
        )
        t(
            "export files are 0600",
            all(oct(os.stat(x).st_mode & 0o777) == "0o600" for x in w),
        )
        t(
            "json valid",
            json.load(open(os.path.join(td, "out", "report.json")))["checks"][
                0
            ]["id"]
            == "a",
        )
        t(
            "bundle readable",
            "netaudit/raw/a.txt"
            in tarfile.open(
                os.path.join(td, "out", "bundle.tar.gz")
            ).getnames(),
        )
    print(f"selftest: {ok} ok, {fail} failed")
    return 1 if fail else 0


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        description="Network audit + export TUI", add_help=True
    )
    ap.add_argument(
        "--plain", action="store_true", help="one-shot text report"
    )
    ap.add_argument("--json", action="store_true", help="one-shot JSON report")
    ap.add_argument(
        "--export",
        metavar="FMTS",
        help="comma list or quoted wildcards: json,md,txt,html,csv,bundle,*",
    )
    ap.add_argument("--out", metavar="DIR", help="export directory")
    ap.add_argument(
        "--offline", action="store_true", help="no external HTTPS request"
    )
    ap.add_argument(
        "--no-redact",
        action="store_true",
        help="do not redact secrets in output",
    )
    ap.add_argument(
        "--readonly", action="store_true", help="disable repair actions"
    )
    ap.add_argument(
        "--name", default="github.com", help="hostname used for DNS tests"
    )
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    ctx = Ctx(a.name, a.offline, not a.no_redact, a.readonly)
    headless = a.plain or a.json or a.export or not sys.stdout.isatty()
    audit = Audit(ctx)
    if headless:
        audit.start()
        audit.wait()
        rep = audit.report()
        if a.export:
            patterns = [x.strip() for x in a.export.split(",") if x.strip()]
            fm, bad = expand_format_patterns(patterns)
            if bad:
                print(
                    f"[error] unknown format pattern(s): {', '.join(bad)}",
                    file=sys.stderr,
                )
                return 2
            for p in export(rep, fm, ctx, a.out):
                print(f"[ok] {p}")
        if a.json:
            print(fmt_json(rep))
        elif a.plain or not a.export:
            print(fmt_txt(rep), end="")
        return 1 if any(c["status"] == "FAIL" for c in rep["checks"]) else 0
    if not ctx.is_root:
        print(
            "note: not root, WireGuard/firewall checks and repairs are limited (use: sudo netaudit)",
            file=sys.stderr,
        )
        time.sleep(1.2)
    try:
        run_tui(ctx)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(
        code
    )  # do not wait for slow probe threads (getent/DNS timeouts) after the user quits

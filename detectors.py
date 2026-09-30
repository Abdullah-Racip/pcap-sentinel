"""
PCAP Sentinel — detectors.

Each detector is a plain function `detect_*(packets) -> list[Finding]`, registered in
DETECTORS at the bottom. To add one: write the function, add it to the dict, done —
the CLI picks it up automatically.
"""
from dataclasses import dataclass, field
from typing import List, Callable
from collections import defaultdict, Counter
import math
import re
import base64

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.packet import Raw

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SYN, ACK = 0x02, 0x10


@dataclass
class Finding:
    detector: str
    title: str
    severity: str
    summary: str
    evidence: List[str] = field(default_factory=list)


# ── helpers ───────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    """Bits/char — high = random-looking (e.g. encoded tunnel payload)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def fmt_pkts(indices, limit=8) -> str:
    shown = ", ".join(f"#{i}" for i in indices[:limit])
    extra = len(indices) - limit
    return shown + (f" … (+{extra} more)" if extra > 0 else "")


# ── SYN flood ───────────────────────────────────────────────────────────────
def detect_syn_flood(packets, syn_threshold=100, ratio_threshold=3.0, min_sources=15):
    """Many bare SYNs to one target, ~no SYN-ACKs, many (spoofed) sources = half-open DoS."""
    syn_idx, syn_srcs, syn_times = defaultdict(list), defaultdict(set), defaultdict(list)
    synack = defaultdict(int)
    for i, pkt in enumerate(packets, start=1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        flags = int(pkt[TCP].flags)
        key = (pkt[IP].dst, int(pkt[TCP].dport))
        if flags & SYN and not flags & ACK:
            syn_idx[key].append(i)
            syn_srcs[key].add(pkt[IP].src)
            syn_times[key].append(float(pkt.time))
        elif flags & SYN and flags & ACK:
            synack[(pkt[IP].src, int(pkt[TCP].sport))] += 1

    findings = []
    for (dst, dport), idx in syn_idx.items():
        n_syn, n_ack, n_src = len(idx), synack.get((dst, dport), 0), len(syn_srcs[(dst, dport)])
        ratio_ok = n_ack == 0 or (n_syn / max(n_ack, 1)) >= ratio_threshold
        if n_syn >= syn_threshold and ratio_ok and n_src >= min_sources:
            span = max(syn_times[(dst, dport)]) - min(syn_times[(dst, dport)])
            rate = n_syn / span if span > 0 else float(n_syn)
            findings.append(Finding(
                "syn_flood", "TCP SYN flood (denial of service)", "HIGH",
                f"{n_syn} half-open SYNs to {dst}:{dport} from {n_src} sources in {span:.2f}s",
                [f"{n_syn} SYN packets (tcp.flags.syn==1 && tcp.flags.ack==0) target {dst}:{dport}",
                 f"only {n_ack} SYN-ACK(s) returned — connections never complete (half-open)",
                 f"{n_src} distinct source IPs, non-completing → likely spoofed",
                 f"rate ≈ {rate:.0f} SYN/s over {span:.2f}s",
                 f"packets: {fmt_pkts(idx)}"]))
    return findings


# ── port scan ────────────────────────────────────────────────────────────
def detect_port_scan(packets, port_threshold=50):
    """One source → many ports on one host (the mirror image of a flood)."""
    ports, idx = defaultdict(set), defaultdict(list)
    for i, pkt in enumerate(packets, start=1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        flags = int(pkt[TCP].flags)
        if flags & SYN and not flags & ACK:
            key = (pkt[IP].src, pkt[IP].dst)
            ports[key].add(int(pkt[TCP].dport))
            idx[key].append(i)

    findings = []
    for (src, dst), dports in ports.items():
        if len(dports) >= port_threshold:
            sample = sorted(dports)[:12]
            findings.append(Finding(
                "port_scan", "TCP port scan (reconnaissance)", "MEDIUM",
                f"{src} probed {len(dports)} ports on {dst}",
                [f"single source {src} sent SYNs to {len(dports)} distinct ports on {dst}",
                 f"ports include: {', '.join(map(str, sample))}{' …' if len(dports) > 12 else ''}",
                 f"packets: {fmt_pkts(idx[(src, dst)])}"]))
    return findings


# ── ARP spoofing ──────────────────────────────────────────────────────────
def detect_arp_spoof(packets):
    """Same IP claimed by more than one MAC = poisoning / MITM."""
    ip_to_macs, ip_mac_pkts = defaultdict(set), defaultdict(list)
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer(ARP) and int(pkt[ARP].op) == 2:      # is-at reply
            ip_to_macs[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
            ip_mac_pkts[(pkt[ARP].psrc, pkt[ARP].hwsrc)].append(i)

    findings = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            lines = [f"IP {ip} is claimed by {len(macs)} different MACs — impersonation:"]
            for mac in macs:
                pk = ip_mac_pkts[(ip, mac)]
                lines.append(f"  • {mac} in {fmt_pkts(pk, limit=5)} ({len(pk)} reply/replies)")
            lines.append("Wireshark flags this as 'duplicate use of <IP> detected'.")
            findings.append(Finding(
                "arp_spoof", "ARP spoofing / cache poisoning (MITM)", "HIGH",
                f"IP {ip} mapped to {len(macs)} MAC addresses", lines))
    return findings


# ── DNS tunnelling ────────────────────────────────────────────────────────
def _parent_domain(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def detect_dns_tunnel(packets, min_queries=20, len_threshold=25, entropy_threshold=3.0):
    """Lots of queries to one domain with long, high-entropy subdomains = data in the QNAME."""
    agg = defaultdict(lambda: {"count": 0, "lens": [], "ent": [], "idx": [], "sample": None})
    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        if int(dns.qr) != 0 or dns.qd is None:
            continue
        try:
            qname = dns.qd.qname.decode("utf-8", "ignore").rstrip(".")
        except Exception:
            continue
        parent = _parent_domain(qname)
        sub = qname[: -len(parent)].rstrip(".") if qname.endswith(parent) else qname
        d = agg[parent]
        d["count"] += 1
        d["lens"].append(len(sub))
        d["ent"].append(shannon_entropy(sub))
        d["idx"].append(i)
        if d["sample"] is None:
            d["sample"] = qname

    findings = []
    for parent, d in agg.items():
        if d["count"] < min_queries:
            continue
        avg_len = sum(d["lens"]) / len(d["lens"])
        avg_ent = sum(d["ent"]) / len(d["ent"])
        if avg_len >= len_threshold and avg_ent >= entropy_threshold:
            findings.append(Finding(
                "dns_tunnel", "DNS tunnelling / exfiltration", "HIGH",
                f"{d['count']} queries to *.{parent} with long, high-entropy subdomains",
                [f"{d['count']} DNS queries to a single parent domain '{parent}'",
                 f"avg subdomain length {avg_len:.0f} chars (normal lookups are short)",
                 f"avg subdomain entropy {avg_ent:.2f} bits/char (random-looking → encoded payload)",
                 f"example QNAME: {d['sample']}",
                 f"packets: {fmt_pkts(d['idx'])}"]))
    return findings


# ── plaintext credentials ─────────────────────────────────────────────────
_FTP_POP = re.compile(r"^(USER|PASS)\s+(.+?)\s*$", re.I | re.M)
_IMAP = re.compile(r"\bLOGIN\s+(\S+)\s+(\S+)", re.I)
_HTTP_POST = re.compile(r"\b(user(?:name)?|login|email|pass(?:word|wd)?)=([^&\s]+)", re.I)
_BASIC = re.compile(r"Authorization:\s*Basic\s+(\S+)", re.I)


def _b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("latin-1", "ignore")
    except Exception:
        return "<undecodable>"


def detect_plaintext_creds(packets):
    """USER/PASS, POST bodies, Basic/AUTH base64, and Telnet transcripts sent in the clear."""
    findings, seen = [], set()
    telnet = defaultdict(list)

    def add(proto, pkt_no, detail):
        if (proto, detail) in seen:
            return
        seen.add((proto, detail))
        findings.append(Finding(
            "plaintext_creds", "Plaintext credentials exposed", "MEDIUM",
            f"{proto} credential sent in the clear",
            [f"packet #{pkt_no} ({proto}): {detail}"]))

    for i, pkt in enumerate(packets, start=1):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        try:
            data = bytes(pkt[Raw].load).decode("latin-1")
        except Exception:
            continue
        ports = {int(pkt[TCP].dport), int(pkt[TCP].sport)}
        if ports & {21, 110}:
            for cmd, val in _FTP_POP.findall(data):
                add("FTP" if 21 in ports else "POP3", i, f"{cmd.upper()} {val}")
        if 143 in ports:
            for u, p in _IMAP.findall(data):
                add("IMAP", i, f"LOGIN {u} {p}")
        if ports & {80, 8080, 8000}:
            for f_, v in _HTTP_POST.findall(data):
                add("HTTP", i, f"{f_}={v}")
            for tok in _BASIC.findall(data):
                add("HTTP", i, f"Basic auth → {_b64(tok)}")
        if ports & {25, 587} and re.search(r"AUTH\s+LOGIN", data, re.I):
            for line in data.splitlines():
                line = line.strip()
                if re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", line):
                    add("SMTP", i, f"AUTH base64 → {_b64(line)}")
        if 23 in ports:
            a, b = sorted([(pkt[IP].src, int(pkt[TCP].sport)), (pkt[IP].dst, int(pkt[TCP].dport))])
            telnet[(a, b)].append((i, data))

    for stream in telnet.values():
        transcript = "".join(t for _, t in stream)
        first = stream[0][0]
        for label, tag in (("login", "username"), ("password", "password")):
            m = re.search(label + r"\s*:\s*([^\r\n]+)", transcript, re.I)
            if m and m.group(1).strip():
                add("Telnet", first, f"{tag}: {m.group(1).strip()}")
    return findings


# ── registry ──────────────────────────────────────────────────────────────
DETECTORS: dict[str, Callable] = {
    "syn_flood": detect_syn_flood,
    "port_scan": detect_port_scan,
    "arp_spoof": detect_arp_spoof,
    "dns_tunnel": detect_dns_tunnel,
    "plaintext_creds": detect_plaintext_creds,
}

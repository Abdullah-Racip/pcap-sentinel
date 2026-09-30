#!/usr/bin/env python3
"""
PCAP Sentinel — offline traffic triage.

Point it at a capture and it flags common network attacks — SYN floods, port scans,
ARP spoofing, DNS tunnelling, and plaintext credential exposure — reporting the
*evidence* (packet numbers, protocol fields, extracted values) for each, not just a label.

    python pcap_sentinel.py capture.pcap
    python pcap_sentinel.py *.pcap --only dns_tunnel,arp_spoof
    python pcap_sentinel.py capture.pcap --json findings.json --no-color
"""
import argparse
import json
import sys

try:
    from scapy.all import rdpcap
except ImportError:
    sys.exit("scapy is required:  pip install scapy")

from detectors import DETECTORS, SEVERITY_ORDER

C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "green": "\033[92m",
    "CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
    "LOW": "\033[94m", "INFO": "\033[96m",
}


def paint(text, key, on=True):
    return f"{C.get(key, '')}{text}{C['reset']}" if on else text


def analyse(path, only=None):
    packets = rdpcap(path)
    findings = []
    for name, fn in DETECTORS.items():
        if only and name not in only:
            continue
        findings.extend(fn(packets))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return len(packets), findings


def print_report(path, n_pkts, findings, colour=True):
    print(paint(f"\n╔═ PCAP Sentinel ═ {path}", "bold", colour))
    print(paint(f"║  {n_pkts} packets analysed · {len(findings)} finding(s)\n", "dim", colour))
    if not findings:
        print(paint("  ✓ No known attack signatures detected.\n", "green", colour))
        return
    for f in findings:
        badge = paint(f" {f.severity} ", f.severity, colour)
        print(f"  [{badge}] {paint(f.title, 'bold', colour)}")
        print(f"          {f.summary}")
        for line in f.evidence:
            print(paint(f"            └ {line}", "dim", colour))
        print()


def main():
    ap = argparse.ArgumentParser(description="Offline PCAP attack-signature triage.")
    ap.add_argument("pcaps", nargs="+", help="capture file(s) to analyse (.pcap/.pcapng)")
    ap.add_argument("--only", help=f"comma-separated detectors ({', '.join(DETECTORS)})")
    ap.add_argument("--json", metavar="FILE", help="also write findings as JSON")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()

    colour = sys.stdout.isatty() and not args.no_color
    only = set(args.only.split(",")) if args.only else None
    if only and (bad := only - set(DETECTORS)):
        sys.exit(f"unknown detector(s): {', '.join(bad)}")

    all_json, worst = {}, 0
    for path in args.pcaps:
        try:
            n_pkts, findings = analyse(path, only)
        except FileNotFoundError:
            print(f"! {path}: not found", file=sys.stderr)
            continue
        print_report(path, n_pkts, findings, colour)
        worst = max([worst] + [SEVERITY_ORDER.get(f.severity, 0) for f in findings])
        all_json[path] = [f.__dict__ for f in findings]

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(all_json, fh, indent=2)
        print(paint(f"→ findings written to {args.json}", "dim", colour))

    sys.exit(2 if worst >= SEVERITY_ORDER["HIGH"] else 0)


if __name__ == "__main__":
    main()

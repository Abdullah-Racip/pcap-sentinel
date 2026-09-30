<h1 align="center">🛰️ PCAP Sentinel</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/built_with-scapy-000000?style=flat-square" alt="scapy"/>
  <img src="https://img.shields.io/badge/type-network_forensics-00FF9C?style=flat-square" alt="type"/>
</p>

<p align="center">
Offline traffic triage — point it at a capture and it flags common network attacks,
and tells you <i>why</i>.
</p>

---

## What it is

I kept practising Wireshark for traffic analysis and noticed I run the same mental checklist
on every capture: *is this a flood? a scan? is someone poisoning ARP? are there creds in the
clear?* **PCAP Sentinel** is that checklist as code. You give it a `.pcap`, it runs a set of
detectors, and for every hit it prints the **evidence** — packet numbers, protocol fields,
extracted values — not just a label. Naming the attack isn't enough; the proof is the point.

| Detector | Catches | Core signal |
|---|---|---|
| `syn_flood` | TCP SYN flood (DoS) | many SYNs, ~no SYN-ACKs, many sources, one target |
| `port_scan` | TCP port scan (recon) | one source → many ports on one host |
| `arp_spoof` | ARP poisoning (MITM) | one IP claimed by more than one MAC |
| `dns_tunnel` | DNS tunnelling / exfil | long, high-entropy subdomains, high query volume to one domain |
| `plaintext_creds` | Cleartext credentials | FTP · Telnet · HTTP · POP3 · IMAP · SMTP |

## Install

```bash
git clone https://github.com/Abdullah-Racip/pcap-sentinel
cd pcap-sentinel
pip install -r requirements.txt
```

## Quick start

```bash
python generate_samples.py               # writes 4 demo captures into ./samples/
python pcap_sentinel.py samples/*.pcap    # analyse them all
```

Then on your own captures:

```bash
python pcap_sentinel.py capture.pcap                 # run every detector
python pcap_sentinel.py *.pcap --only dns_tunnel     # just one (or a comma list)
python pcap_sentinel.py capture.pcap --json out.json # also export findings as JSON
```

It exits `2` when anything **HIGH** or above is found, so it drops straight into a pipeline
or CI check.

## Sample run

```
$ python pcap_sentinel.py samples/02_syn_flood.pcap

╔═ PCAP Sentinel ═ samples/02_syn_flood.pcap
║  300 packets analysed · 1 finding(s)

  [ HIGH ] TCP SYN flood (denial of service)
          300 half-open SYNs to 10.0.0.5:80 from 300 sources in 0.30s
            └ 300 SYN packets (tcp.flags.syn==1 && tcp.flags.ack==0) target 10.0.0.5:80
            └ only 0 SYN-ACK(s) returned — connections never complete (half-open)
            └ 300 distinct source IPs, non-completing → likely spoofed
            └ rate ≈ 1014 SYN/s over 0.30s
            └ packets: #1, #2, #3, #4, #5, #6, #7, #8 … (+292 more)
```

```
$ python pcap_sentinel.py samples/01_plaintext_creds.pcap

  [ MEDIUM ] Plaintext credentials exposed · FTP    → #6: USER mvictor / #10: PASS Summer2026!
  [ MEDIUM ] Plaintext credentials exposed · HTTP   → #17: username=admin & password=Pa55w0rd_99
  [ MEDIUM ] Plaintext credentials exposed · Telnet → #24: sysadmin / R00tM3N0w
```

## How each detector reasons (the *why*)

- **SYN flood** — a normal session is SYN → SYN-ACK → ACK; a flood sends floods of bare SYNs
  and never completes the handshake, exhausting the target's half-open table. Fires when the
  SYN-to-SYN-ACK ratio is lopsided *and* the sources are many (spoofed).
- **Port scan** — the mirror image: **one** source touching **many** ports on one host.
- **ARP spoofing** — ARP has no authentication, so an attacker answers "that IP is at *my*
  MAC". The tell is a single IP mapping to two different MACs.
- **DNS tunnelling** — data smuggled inside the QNAME makes subdomains long and random-looking;
  measured via average subdomain **length** and **Shannon entropy** per parent domain.
- **Plaintext creds** — these protocols predate TLS, so credentials ride in the clear.
  Parses FTP/POP3 `USER`/`PASS`, IMAP `LOGIN`, HTTP POST bodies + Basic-auth (base64-decoded),
  SMTP `AUTH LOGIN`, and reconstructs the Telnet login transcript.

## Extending it

Each detector is a function `detect_*(packets) -> [Finding]` in [`detectors.py`](./detectors.py).
Write one, add it to the `DETECTORS` dict, and it appears in the CLI automatically. Next on my
list: MAC flooding, DHCP starvation / rogue servers, DNS spoofing, and ICMP tunnelling.

---

<p align="center"><sub>Built for learning — run it only on captures you're authorised to analyse.</sub></p>

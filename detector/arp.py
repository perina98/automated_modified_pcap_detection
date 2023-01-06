##################################################
## This modules checks all arp packets, gathers all IP addresses and compares them with the IP addresses in whole pcap
##################################################
## File: arp.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from scapy.layers.tls import *

def get_failed_arp_macs(pkts):
    arp_macs = []
    all_macs = []
    for pkt in pkts:
        if pkt.haslayer(ARP):
            arp_macs.append(pkt[Ether].src)
            arp_macs.append(pkt[Ether].dst)
        if pkt.haslayer(IP):
            all_macs.append({'src': pkt[Ether].src, 'dst': pkt[Ether].dst})

    failed_macs = 0
    arp_set = set(arp_macs)
    for mac in all_macs:
        if mac['src'] not in arp_set and mac['dst'] not in arp_set:
            failed_macs += 1
    
    return failed_macs
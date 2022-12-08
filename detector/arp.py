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
import ipaddress

def get_failed_arp_ips(pkts):
    arp_ips = []
    all_ips = []
    for pkt in pkts:
        if pkt.haslayer(ARP):
            if ipaddress.IPv4Address(pkt[ARP].psrc) in ipaddress.IPv4Network('4.122.55.0/24') and \
               ipaddress.IPv4Address(pkt[ARP].pdst) in ipaddress.IPv4Network('4.122.55.0/24'):
                arp_ips.append(pkt[ARP].psrc)
                arp_ips.append(pkt[ARP].pdst)
        if pkt.haslayer(IP):
            if ipaddress.IPv4Address(pkt[IP].src) in ipaddress.IPv4Network('4.122.55.0/24') and \
               ipaddress.IPv4Address(pkt[IP].dst) in ipaddress.IPv4Network('4.122.55.0/24'):
                all_ips.append(pkt[IP].src)
                all_ips.append(pkt[IP].dst)

    failed_ips = 0
    for ip in set(all_ips):
        if ip not in set(arp_ips):
            failed_ips += 1
    
    return failed_ips
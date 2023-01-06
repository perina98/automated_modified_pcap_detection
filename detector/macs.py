##################################################
## This modules checks all packets and makes a map of all MAC addresses and their IP addresses
##################################################
## File: macs.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
import ipaddress

def get_macs(pkts):
    macs = {}
    for pkt in pkts:
        if pkt.haslayer(IP):
            if macs.get(pkt[IP].src) == None:
                macs[pkt[IP].src] = [pkt[Ether].src]
            else:
                macs[pkt[IP].src].append(pkt[Ether].src)
            
            if macs.get(pkt[IP].dst) == None:
                macs[pkt[IP].dst] = [pkt[Ether].dst]
            else:
                macs[pkt[IP].dst].append(pkt[Ether].dst)
    return macs

def get_failed_mac_maps(pkts):
    macs = get_macs(pkts)
    failed = 0
    for ip in macs:
        if len(set(macs[ip])) > 1:
            failed += 1
    return failed
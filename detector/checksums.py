##################################################
## This modules checks the checksum of the packet and compares it with the original checksum
##################################################
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

# calculate the checksum of the packet
# if the checksum is not the same as the original packet, the packet is modified
# returns true if the packet checksum is modified, false otherwise
# delete checksum and force recalculation by calling pkt.__class__(bytes(pkt))
# checks if the checksum is modified in TCP, UDP, IP and ICMP layers

from scapy.all import *
from scapy.layers.tls import *

def check_checksum(pkt):
    
    if pkt.haslayer(TCP):
        original_checksum = pkt[TCP].chksum
        del pkt[TCP].chksum
        pkt = pkt.__class__(bytes(pkt))
        calculated_checksum = pkt[TCP].chksum
        if original_checksum != calculated_checksum:
            return True

    if pkt.haslayer(UDP):
        original_checksum = pkt[UDP].chksum
        del pkt[UDP].chksum
        pkt = pkt.__class__(bytes(pkt))
        calculated_checksum = pkt[UDP].chksum
        if original_checksum != calculated_checksum:
            return True
    
    if pkt.haslayer(IP):
        original_checksum = pkt[IP].chksum
        del pkt[IP].chksum
        pkt = pkt.__class__(bytes(pkt))
        calculated_checksum = pkt[IP].chksum
        if original_checksum != calculated_checksum:
            return True
    
    if pkt.haslayer(ICMP):
        original_checksum = pkt[ICMP].chksum
        del pkt[ICMP].chksum
        pkt = pkt.__class__(bytes(pkt))
        calculated_checksum = pkt[ICMP].chksum
        if original_checksum != calculated_checksum:
            return True

    return False

def get_failed_checksums(pkts):
    failed_checksums = 0
    for pkt in pkts:
        if check_checksum(pkt):
            failed_checksums += 1
    return failed_checksums
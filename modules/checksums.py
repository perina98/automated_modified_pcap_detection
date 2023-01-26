##################################################
## This module checks the checksum of the packet and compares it with the original checksum
##################################################
## File: checksums.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from scapy.layers.tls import *

class Checksums():
    def check_checksum(self,pkt):
        modified = False
        if pkt.haslayer(TCP):
            original_checksum = pkt[TCP].chksum
            del pkt[TCP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[TCP].chksum
            if original_checksum != calculated_checksum:
                modified = True
                return modified

        if pkt.haslayer(UDP):
            original_checksum = pkt[UDP].chksum
            del pkt[UDP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[UDP].chksum
            if original_checksum != calculated_checksum:
                modified = True
                return modified
        
        if pkt.haslayer(IP):
            original_checksum = pkt[IP].chksum
            del pkt[IP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[IP].chksum
            if original_checksum != calculated_checksum:
                modified = True
                return modified
        
        if pkt.haslayer(ICMP):
            original_checksum = pkt[ICMP].chksum
            del pkt[ICMP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[ICMP].chksum
            if original_checksum != calculated_checksum:
                modified = True
                return modified

        return modified

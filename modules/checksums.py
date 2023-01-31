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
        original_checksums = {
            "TCP": None,
            "UDP": None,
            "IP": None,
            "ICMP": None
        }

        if pkt.haslayer(TCP):
            original_checksums["TCP"] = pkt[TCP].chksum
            del pkt[TCP].chksum

        if pkt.haslayer(UDP):
            original_checksums["UDP"] = pkt[UDP].chksum
            del pkt[UDP].chksum
        
        if pkt.haslayer(IP):
            original_checksums["IP"] = pkt[IP].chksum
            del pkt[IP].chksum
        
        if pkt.haslayer(ICMP):
            original_checksums["ICMP"] = pkt[ICMP].chksum
            del pkt[ICMP].chksum

        pkt = pkt.__class__(bytes(pkt))

        if (original_checksums["TCP"] != None and original_checksums["TCP"] != pkt[TCP].chksum) or \
            (original_checksums["UDP"] != None and original_checksums["UDP"] != pkt[UDP].chksum) or \
            (original_checksums["IP"] != None and original_checksums["IP"] != pkt[IP].chksum) or \
            (original_checksums["ICMP"] != None and original_checksums["ICMP"] != pkt[ICMP].chksum):    
            modified = True

        return modified

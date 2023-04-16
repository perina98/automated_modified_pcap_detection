##################################################
## This module checks variaty of information about packet structure for any inconsistencies
##################################################
## File: misc.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from scapy.layers.tls import *
import modules.functions as functions

class Miscellaneous():
    '''
    Class for checking various information about packet structure for any inconsistencies
    '''
    def __init__(self):
        '''
        Constructor
        Args:

        Returns:
            None
        '''
        self.protocols = functions.Functions().get_protocols()

    def check_protocol(self, pkt):
        '''
        Check the packet protocol number vs its port on both sides
        Args:
            pkt (mixed): packet

        Returns:
            None
        '''
        if pkt.haslayer(IP):
            protocol = pkt[IP].proto
            if protocol in self.protocols:
                sport = pkt[TCP].sport if protocol == 6 else pkt[UDP].sport
                dport = pkt[TCP].dport if protocol == 6 else pkt[UDP].dport
                if sport not in self.protocols[protocol] and dport not in self.protocols[protocol]:
                    return True
        return False

    def check_checksum(self,pkt):
        '''
        Constructor
        Args:
            pkt (scapy packet): packet to check

        Returns:
            None
        '''
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

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

    def check_packet_length(self, pkt):
        '''
        Check if the packet length is correct
        Args:
            pkt (scapy packet): packet to check

        Returns:
            None
        '''

        length = len(pkt)
        rawlen = 0

        if pkt.haslayer(Raw):
            rawlen = len(pkt[Raw])

        if pkt.haslayer(Ether):
            if len(pkt) != length:
                return True
        
        # Ethernet header
        length -= 14

        if pkt.haslayer(IP):
            # length - Ethernet header
            if pkt[IP].len != length:
                return True
            
            # IP header
            length -= pkt[IP].ihl * 4

        if pkt.haslayer(UDP):
            if length != pkt[UDP].len:
                return True
            # UDP header
            length -= 8

        if pkt.haslayer(TCP):
            if length != len(pkt[TCP]):
                return True
            # TCP header
            length -= pkt[TCP].dataofs * 4

        if pkt.haslayer(TLS):
            # pkt[TLS].len is the length of the TLS record
            # payload is the length of the TLS record payload
            # 5 is the length of the TLS record header
            payload = pkt[TLS].payload
            if length != pkt[TLS].len + 5 + len(payload):
                return True
        
        return False
    
    def check_invalid_payload(self, pkt):
        '''
        Check if the packet payload ends with multiple 0x00 bytes or if it ends with 16 same bytes
        Args:
            pkt (scapy packet): packet to check

        Returns:
            None
        '''
        if pkt.haslayer(Raw):
            if pkt[Raw].load.endswith(b'\x00\x00\x00\x00\x00\x00\x00\x00'):
                return True
            
            # check if last 16 bytes are the same
            if len(pkt[Raw].load) >= 16:
                last_16 = pkt[Raw].load[-16:]
                if last_16 == last_16[0:1] * 16:
                    return True
            
        return False
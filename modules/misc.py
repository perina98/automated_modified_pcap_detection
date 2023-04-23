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
        self.snaplen_context = []

    def check_ports(self, packet):
        '''
        Check the packet protocol number vs its port on both sides
        Args:
            packet (mixed): packet

        Returns:
            bool: True if the protocol number is not consistent with the port number, False otherwise
        '''
        if packet.haslayer(IP):
            protocol = packet[IP].proto
            if protocol in self.protocols:
                if not packet.haslayer(TCP) and protocol == 6:
                    return True
                elif not packet.haslayer(UDP) and protocol == 17:
                    return True
                sport = packet[TCP].sport if protocol == 6 else packet[UDP].sport
                dport = packet[TCP].dport if protocol == 6 else packet[UDP].dport
                if sport not in self.protocols[protocol] and dport not in self.protocols[protocol]:
                    return True
        return False

    def check_checksum(self, packet):
        '''
        Check if the checksum is correct for TCP, UDP, IP and ICMP
        Args:
            packet (scapy packet): packet to check

        Returns:
            bool: True if at least one checksum is incorrect, False otherwise
        '''
        original_checksums = {
            "TCP": None,
            "UDP": None,
            "IP": None,
            "ICMP": None
        }

        if packet.haslayer(TCP):
            original_checksums["TCP"] = packet[TCP].chksum
            del packet[TCP].chksum

        if packet.haslayer(UDP):
            original_checksums["UDP"] = packet[UDP].chksum
            del packet[UDP].chksum
        
        if packet.haslayer(IP):
            original_checksums["IP"] = packet[IP].chksum
            del packet[IP].chksum
        
        if packet.haslayer(ICMP):
            original_checksums["ICMP"] = packet[ICMP].chksum
            del packet[ICMP].chksum

        # force recalculation of checksums
        packet = packet.__class__(bytes(packet))

        if (original_checksums["TCP"] != None and original_checksums["TCP"] != packet[TCP].chksum) or \
            (original_checksums["UDP"] != None and original_checksums["UDP"] != packet[UDP].chksum) or \
            (original_checksums["IP"] != None and original_checksums["IP"] != 0 and original_checksums["IP"] != packet[IP].chksum) or \
            (original_checksums["ICMP"] != None and original_checksums["ICMP"] != packet[ICMP].chksum):    
            return True

        return False

    def check_packet_length(self, packet):
        '''
        Check if the packet length is correct
        Args:
            packet (scapy packet): packet to check

        Returns:
            bool: True if the packet length is incorrect False otherwise
        '''
        length = len(packet)

        # Ethernet header
        length -= 14

        if packet.haslayer(Padding):
            length -= len(packet[Padding])
        
        if packet.haslayer(IP):
            if packet[IP].len != length:
                return True
            
            # IP header
            length -= packet[IP].ihl * 4
        
        if packet.haslayer(IPv6):
            # IPv6 header
            length -= 40

        if packet.haslayer(UDP):
            if length != packet[UDP].len:
                return True
            # UDP header
            length -= 8
        if packet.haslayer(TCP):
            if packet.haslayer(Padding):
                length += len(packet[Padding])
            if length != len(packet[TCP]):
                return True
            # TCP header
            length -= packet[TCP].dataofs * 4
        if packet.haslayer(TLS):
            # packet[TLS].len is the length of the TLS record
            # payload is the length of the TLS record payload
            # 5 is the length of the TLS record header
            payload = packet[TLS].payload
            if length != packet[TLS].deciphered_len + 5 + len(payload):
                return True
        if packet.haslayer(NTP):
            if length != 48:
                return True
        return False
    
    def check_invalid_payload(self, packet):
        '''
        Check if the packet payload ends with multiple 0x00 bytes or if it ends with 16 same bytes
        Args:
            packet (scapy packet): packet to check

        Returns:
            bool: True if the packet payload is invalid, False otherwise
        '''
        if packet.haslayer(Raw):
            if packet[Raw].load.endswith(b'\x00\x00\x00\x00\x00\x00\x00\x00'):
                return True
            
            # check if last 16 bytes are the same
            if len(packet[Raw].load) >= 16:
                last_16 = packet[Raw].load[-16:]
                if last_16 == last_16[0:1] * 16:
                    return True
            
        return False
    
    def check_frame_len_and_cap_len(self, packet):
        '''
        Check if the packet frame length and captured length are the same
        If not, it indicates that the packet was truncated
        Args:
            packet (scapy packet): packet to check

        Returns:
            bool: True if the packet was truncated, False otherwise
        '''
        if hasattr(packet, 'wirelen'):
            if packet.wirelen != len(packet):
                return True
        else:
            return True
        return False
    
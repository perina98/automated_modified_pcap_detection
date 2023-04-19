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

    def check_protocol(self, packet):
        '''
        Check the packet protocol number vs its port on both sides
        Args:
            packet (mixed): packet

        Returns:
            None
        '''
        if packet.haslayer(IP):
            protocol = packet[IP].proto
            if protocol in self.protocols:
                sport = packet[TCP].sport if protocol == 6 else packet[UDP].sport
                dport = packet[TCP].dport if protocol == 6 else packet[UDP].dport
                if sport not in self.protocols[protocol] and dport not in self.protocols[protocol]:
                    return True
        return False

    def check_checksum(self,packet):
        '''
        Constructor
        Args:
            packet (scapy packet): packet to check

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

        packet = packet.__class__(bytes(packet))

        if (original_checksums["TCP"] != None and original_checksums["TCP"] != packet[TCP].chksum) or \
            (original_checksums["UDP"] != None and original_checksums["UDP"] != packet[UDP].chksum) or \
            (original_checksums["IP"] != None and original_checksums["IP"] != packet[IP].chksum) or \
            (original_checksums["ICMP"] != None and original_checksums["ICMP"] != packet[ICMP].chksum):    
            print ("Checksums are not equal")
            print(packet.time, packet.summary())
            modified = True

        return modified

    def check_packet_length(self, packet):
        '''
        Check if the packet length is correct
        Args:
            packet (scapy packet): packet to check

        Returns:
            None
        '''

        length = len(packet)
        rawlen = 0

        if packet.haslayer(Raw):
            rawlen = len(packet[Raw])

        if packet.haslayer(Ether):
            if len(packet) != length:
                return True
        
        # Ethernet header
        length -= 14

        if packet.haslayer(IP):
            # length - Ethernet header
            if packet[IP].len != length:
                return True
            
            # IP header
            length -= packet[IP].ihl * 4

        if packet.haslayer(UDP):
            if length != packet[UDP].len:
                return True
            # UDP header
            length -= 8

        if packet.haslayer(TCP):
            if length != len(packet[TCP]):
                return True
            # TCP header
            length -= packet[TCP].dataofs * 4

        if packet.haslayer(TLS):
            # packet[TLS].len is the length of the TLS record
            # payload is the length of the TLS record payload
            # 5 is the length of the TLS record header
            payload = packet[TLS].payload
            if length != packet[TLS].len + 5 + len(payload):
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
            None
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
    

    def check_ct_timestamp(self, packet):
        if packet.haslayer(TLS) and packet.haslayer(TLSServerHello):
            if hasattr(packet[TLSServerHello],'gmt_unix_time'):
                if packet[TLSServerHello].gmt_unix_time <= packet.time:
                    return True
        return False
    
    def check_frame_len_and_cap_len(self, packet):
        if hasattr(packet, 'len'):
            if packet.len != len(packet):
                return True
        else:
            return True
        return False
    
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
    def get_checksums(self,pkt):
        checksums = {
            'tcp_checksum': None,
            'udp_checksum': None,
            'ip_checksum': None,
            'icmp_checksum': None,
            'tcp_checksum_calculated': None,
            'udp_checksum_calculated': None,
            'ip_checksum_calculated': None,
            'icmp_checksum_calculated': None
        }
        if pkt.haslayer(TCP):
            original_checksum = pkt[TCP].chksum
            del pkt[TCP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[TCP].chksum
            checksums['tcp_checksum'] = original_checksum
            checksums['tcp_checksum_calculated'] = calculated_checksum

        if pkt.haslayer(UDP):
            original_checksum = pkt[UDP].chksum
            del pkt[UDP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[UDP].chksum
            checksums['udp_checksum'] = original_checksum
            checksums['udp_checksum_calculated'] = calculated_checksum
        
        if pkt.haslayer(IP):
            original_checksum = pkt[IP].chksum
            del pkt[IP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[IP].chksum
            checksums['ip_checksum'] = original_checksum
            checksums['ip_checksum_calculated'] = calculated_checksum
        
        if pkt.haslayer(ICMP):
            original_checksum = pkt[ICMP].chksum
            del pkt[ICMP].chksum
            pkt = pkt.__class__(bytes(pkt))
            calculated_checksum = pkt[ICMP].chksum
            checksums['icmp_checksum'] = original_checksum
            checksums['icmp_checksum_calculated'] = calculated_checksum

        return checksums
        
    def check_checksum(self,row):
        if row[0] != row[1] or \
            row[2] != row[3] or \
            row[4] != row[5] or \
            row[6] != row[7]:
            return True

        return False

    def get_failed_checksums(self,detector,id_pcap):
        count = 0
        for row in detector.db.get_packets(id_pcap, detector.db_cursor, ["tcp_checksum", "tcp_checksum_calculated", "udp_checksum", "udp_checksum_calculated", "ip_checksum", "ip_checksum_calculated", "icmp_checksum", "icmp_checksum_calculated"]):
            if self.check_checksum(row):
                count += 1
            
        return count


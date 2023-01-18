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

class Arp():
    def get_failed_arp_ips(self, detector, id_pcap):
        arp_macs = []
        ip_macs = []
        for row in detector.db.get_packets(id_pcap, detector.db_cursor, ["type", "eth_src", "eth_dst"]):
            if row[0] == 2054:
                arp_macs.append(row[1])
                arp_macs.append(row[2])
            if row[0] == 2048:
                ip_macs.append({'src': row[1], 'dst': row[2]})

        failed_macs = 0
        arp_set = set(arp_macs)
        for mac in ip_macs:
            if mac['src'] not in arp_set and mac['dst'] not in arp_set:
                failed_macs += 1
        
        return failed_macs
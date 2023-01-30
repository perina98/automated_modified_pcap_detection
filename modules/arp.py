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
from modules.db import Packet

class Arp():
    def get_failed_arp_ips(self, id_pcap, session):
        arp_macs = []
        ip_macs = []

        for row in session.query(Packet).filter(Packet.id_pcap == id_pcap).all():
            if row.type == 2054:
                arp_macs.append(row.eth_src)
                arp_macs.append(row.eth_dst)
            if row.type == 2048:
                ip_macs.append({'src': row.eth_src, 'dst': row.eth_dst})
                
        failed_macs = 0
        arp_set = set(arp_macs)
        for mac in ip_macs:
            if mac['src'] not in arp_set and mac['dst'] not in arp_set:
                failed_macs += 1
        
        return failed_macs
##################################################
## This modules checks all packets and makes a map of all MAC addresses and their IP addresses
##################################################
## File: macs.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from modules.db import Packet

class Macs():
    def get_macs(self, pkts):
        macs = {}
        for row in pkts:
            if row.type == 2048:
                if macs.get(row.ip_src) == None:
                    macs[row.ip_src] = [row.eth_src]
                else:
                    macs[row.ip_src].append(row.eth_src)

                if macs.get(row.ip_dst) == None:
                    macs[row.ip_dst] = [row.eth_dst]
                else:
                    macs[row.ip_dst].append(row.eth_dst)

        return macs

    def get_failed_mac_maps(self, id_pcap, session):
        macs = self.get_macs(session.query(Packet).filter(Packet.id_pcap == id_pcap).all())
        failed = 0
        for ip in macs:
            if len(set(macs[ip])) > 1:
                failed += 1
        return failed
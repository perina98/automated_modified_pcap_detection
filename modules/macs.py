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

class Macs():
    def get_macs(self, pkts):
        macs = {}
        for row in pkts:
            if row[0] == 2048:
                if macs.get(row[3]) == None:
                    macs[row[3]] = [row[1]]
                else:
                    macs[row[3]].append(row[1])
                
                if macs.get(row[4]) == None:
                    macs[row[4]] = [row[2]]
                else:
                    macs[row[4]].append(row[2])
        return macs

    def get_failed_mac_maps(self, detector, id_pcap):
        macs = self.get_macs(detector.db.get_packets(id_pcap, detector.db_cursor, ["type", "eth_src", "eth_dst", "ip_src", "ip_dst"]))
        failed = 0
        for ip in macs:
            if len(set(macs[ip])) > 1:
                failed += 1
        return failed
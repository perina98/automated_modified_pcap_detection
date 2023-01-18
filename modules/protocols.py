##################################################
## This modules checks the packet protocol number vs its port on both sides
##################################################
## File: protocols.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from scapy.layers.tls import *
import json

class Protocols():
    def __init__(self):
        # load arrays of ports from TCPS.json and UDPS.json
        with open('static/TCPS.json') as f:
            self.TCPS = set(json.load(f))
        with open('static/UDPS.json') as f:
            self.UDPS = set(json.load(f))


    # check the packet protocol number vs its port on both sides
    def check_protocol(self, row):
        if row[0] == 6 and (row[1] not in self.TCPS and row[2] not in self.TCPS):
            return True
        if row[0] == 17 and (row[1] not in self.UDPS and row[2] not in self.UDPS):
            return True
        return False

    def get_failed_protocols(self, detector, id_pcap):
        # get the failed protocols
        count = 0
        for row in detector.db.get_packets(id_pcap, detector.db_cursor, ["protocol", "port_src", "port_dst"]):
            if self.check_protocol(row):
                count += 1
        return count
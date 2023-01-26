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
    def check_protocol(self, pkt):
        if pkt.haslayer(IP):
            if pkt[IP].proto == 6 and (pkt[TCP].sport not in self.TCPS and pkt[TCP].dport not in self.TCPS):
                return True
            if pkt[IP].proto == 17 and (pkt[UDP].sport not in self.UDPS and pkt[UDP].dport not in self.UDPS):
                return True
        return False

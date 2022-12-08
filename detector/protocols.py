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

# load arrays of ports from TCPS.json and UDPS.json
with open('detector/TCPS.json') as f:
    TCPS = set(json.load(f))
with open('detector/UDPS.json') as f:
    UDPS = set(json.load(f))

# check the packet protocol number vs its port on both sides
def check_protocol(packet):
    if packet.haslayer(IP):
        if packet[IP].proto == 6 and (packet[TCP].sport not in TCPS and packet[TCP].dport not in TCPS):
            return True
        if packet[IP].proto == 17 and (packet[UDP].sport not in UDPS and packet[UDP].dport not in UDPS):
            return True
    return False

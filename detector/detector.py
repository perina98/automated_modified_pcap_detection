##################################################
## Detect changes and modifications in pcap files
##################################################
## File: detector.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

# calculate the checksum of the packet
# if the checksum is not the same as the original packet, the packet is modified
# returns true if the packet checksum is modified, false otherwise
# delete checksum and force recalculation by calling pkt.__class__(bytes(pkt))
# checks if the checksum is modified in TCP, UDP, IP and ICMP layers

import os
import logging
import checksums
from scapy.all import *
from scapy.layers.tls import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


DATASET_DIR = '../dataset'

# read dir and get all pcap files
def get_pcaps():
    pcaps = []
    for file in os.listdir(DATASET_DIR):
        if file.endswith(".pcap"):
            pcaps.append(DATASET_DIR+'/'+file)
    return pcaps

# read pcap file from DATASET_DIR and check if it is modified
def check_pcap(pcap):
    load_layer('tls')
    pcap_modifications = {}
    pkts = rdpcap(pcap)
    pcap_modifications["failed_checksums"] = checksums.get_failed_checksums(pkts)

    print (pcap," pcap_modifications['failed_checksums'] = ", str(pcap_modifications["failed_checksums"]) + "/" + str(len(pkts)))


if __name__ == '__main__':
    pcaps = get_pcaps()

    for pcap in pcaps:
        check_pcap(DATASET_DIR+'/'+pcap)

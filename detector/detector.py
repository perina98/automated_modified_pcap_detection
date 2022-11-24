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

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

import argparse 
import os
import logging
from detector import checksums
from scapy.all import *
from scapy.layers.tls import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# read dir and get all pcap files
def get_dataset_pcaps(dir):
    pcaps = []
    for file in os.listdir(dir):
        if file.endswith(".pcap"):
            pcaps.append(dir+'/'+file)
    return pcaps

# read pcap file and check if it is modified
def check_pcap(pcap_path):
    number_of_packets = int(os.popen('tshark -r '+pcap_path+' | wc -l').read())

    load_layer('tls')
    pcap_modifications = {}
    pkts = PcapReader(pcap_path)
    pcap_modifications["failed_checksums"] = checksums.get_failed_checksums(pkts)

    print (pcap_path," pcap_modifications['failed_checksums'] = ", str(pcap_modifications["failed_checksums"]) + "/" + str(number_of_packets))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_pcap", metavar="PCAP_FILE_PATH", help="Input PCAP file path", required=False, type=str)
    parser.add_argument("-d", "--dataset_dir", metavar="DATASET_DIR", help="Run dataset on dataset directory", required=False, type=str)
    args = parser.parse_args()

    if args.dataset_dir:
        pcaps = get_dataset_pcaps(args.dataset_dir)
        for pcap in pcaps:
            check_pcap(pcap)
        exit(0)

    if args.input_pcap:
        if not args.input_pcap.endswith(".pcap"):
            print('Input file is not pcap')
            exit(1)
        check_pcap(args.input_pcap)
        exit(0)

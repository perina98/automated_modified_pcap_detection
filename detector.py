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
from modules import checksums, protocols, arp, macs, db
from modules.db import Pcap, Packet
from static import constants
from scapy.all import *
from scapy.layers.tls import *
from tqdm import tqdm

import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Detector():
    def __init__(self):
        self.pcaps = None
        self.args = self.get_args()
        self.engine = create_engine('sqlite:///' + constants.DATABASE)
        self.session = sessionmaker(bind=self.engine)()
        self.db = db.Database()
        self.checksums = checksums.Checksums()

        logging.basicConfig(level=self.args.log.upper(), format='%(message)s')
        self.log = logging.getLogger(__name__)

        load_layer('tls')
        self.log.debug("Ensuring database exists")
        self.db.ensure_db(self.engine)


    def run(self):
        if self.args.dataset_dir:
            pcaps = self.get_dataset_pcaps()
            for pcap in pcaps:
                id_pcap = self.db.save_pcap(self.session, pcap)
                self.check_pcap(pcap, id_pcap)
            exit(0)

        if self.args.input_pcap:
            if not self.args.input_pcap.endswith(".pcap"):
                print('Input file is not pcap')
                exit(1)
            id_pcap = self.db.save_pcap(self.session, self.args.input_pcap)
            self.check_pcap(self.args.input_pcap, id_pcap)
            exit(0)
    
    def get_pcap_packets_count(self, pcap_path):
        num = os.popen("capinfos -c -M " + pcap_path + " | grep -oP \"\s{3}\d+\"").read()
        if num == '':
            return 0
        return int(num)

    def get_args(self):
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-i", "--input_pcap", metavar="PCAP_FILE_PATH", help="Input PCAP file path", required=False, type=str)
        group.add_argument("-d", "--dataset_dir", metavar="DATASET_DIR", help="Run dataset on dataset directory", required=False, type=str)
        parser.add_argument("-l", "--log", choices=["debug", "info", "warning", "error", "critical"], help="Log level", required=False, default="INFO")
        args = parser.parse_args()
        return args

    def get_dataset_pcaps(self):
        pcaps = []
        for file in os.listdir(self.args.dataset_dir):
            if file.endswith(".pcap"):
                pcaps.append(self.args.dataset_dir+'/'+file)
        return pcaps

    # read pcap file and check if it is modified
    def check_pcap(self, pcap_path, id_pcap):
        packet_count = self.get_pcap_packets_count(self.args.input_pcap)

        pcap_modifications = {
            'failed_checksums': 0,
            'failed_protocols': 0,
            'failed_arp_ips': 0,
            'failed_macs_map': 0
        }

        pkts = PcapReader(pcap_path)
        protos = protocols.Protocols()
        for pkt in tqdm(pkts, desc="Checking pcap", unit=" packets", total=packet_count):
            if self.checksums.check_checksum(pkt):
                pcap_modifications["failed_checksums"] += 1

            if protos.check_protocol(pkt):
                pcap_modifications["failed_protocols"] += 1

            self.db.save_packet(self.session, id_pcap, pkt)

        self.session.commit()

        pcap_modifications["failed_arp_ips"] = arp.Arp().get_failed_arp_ips(id_pcap, self.session)
        pcap_modifications["failed_macs_map"] = macs.Macs().get_failed_mac_maps(id_pcap, self.session)


        print (pcap_path," pcap_modifications['failed_checksums'] = ", str(pcap_modifications["failed_checksums"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_protocols'] = ", str(pcap_modifications["failed_protocols"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_arp_ips'] = ", str(pcap_modifications["failed_arp_ips"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_macs_map'] = ", str(pcap_modifications["failed_macs_map"]) + "/" + str(packet_count))

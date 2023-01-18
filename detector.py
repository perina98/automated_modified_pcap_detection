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
import sqlite3
from modules import checksums, protocols, arp, macs, db
from static import constants
from scapy.all import *
from scapy.layers.tls import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Detector():
    def __init__(self):
        self.pcaps = None
        self.args = self.get_args()
        self.database = constants.DATABASE
        self.db_conn = sqlite3.connect(constants.DATABASE)
        self.db_cursor = self.db_conn.cursor()
        self.db = db.Database()

        self.checksums = checksums.Checksums()

        logging.basicConfig(level=self.args.log.upper(), format='%(message)s')
        self.log = logging.getLogger(__name__)

        load_layer('tls')
        self.log.debug("Ensuring database exists")
        self.db.ensure_db(self.db_cursor)


    def run(self):
        if self.args.dataset_dir:
            pcaps = self.get_dataset_pcaps()
            for pcap in pcaps:
                db.Database().load(self, pcap, self.get_pcap_packets_count(pcap))
                self.check_pcap(pcap)
            exit(0)

        if self.args.input_pcap:
            if not self.args.input_pcap.endswith(".pcap"):
                print('Input file is not pcap')
                exit(1)
            self.db.load(self, self.args.input_pcap, self.get_pcap_packets_count(self.args.input_pcap))
            self.check_pcap(self.args.input_pcap)
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

    # get number of packets in pcap file
    def get_pcap_info(self, pcap_path):
        self.db_cursor.execute("SELECT id_pcap, COUNT(*) FROM packet WHERE id_pcap = (SELECT id_pcap FROM pcap WHERE path = ?)", (pcap_path,))
        result = self.db_cursor.fetchone()
        return {'id_pcap': result[0], 'number_of_packets': result[1]}

    # read pcap file and check if it is modified
    def check_pcap(self, pcap_path):
        info = self.get_pcap_info(pcap_path)

        pcap_modifications = {
            'failed_checksums': 0,
            'failed_protocols': 0,
            'failed_arp_ips': 0,
            'failed_macs_map': 0
        }

        pcap_modifications["failed_checksums"] = self.checksums.get_failed_checksums(self,info["id_pcap"])
        pcap_modifications["failed_protocols"] = protocols.Protocols().get_failed_protocols(self,info["id_pcap"])
        pcap_modifications["failed_arp_ips"] = arp.Arp().get_failed_arp_ips(self,info["id_pcap"])
        pcap_modifications["failed_macs_map"] = macs.Macs().get_failed_mac_maps(self,info["id_pcap"])

        print (pcap_path," pcap_modifications['failed_checksums'] = ", str(pcap_modifications["failed_checksums"]) + "/" + str(info["number_of_packets"]))
        print (pcap_path," pcap_modifications['failed_protocols'] = ", str(pcap_modifications["failed_protocols"]) + "/" + str(info["number_of_packets"]))
        print (pcap_path," pcap_modifications['failed_arp_ips'] = ", str(pcap_modifications["failed_arp_ips"]) + "/" + str(info["number_of_packets"]))
        print (pcap_path," pcap_modifications['failed_macs_map'] = ", str(pcap_modifications["failed_macs_map"]) + "/" + str(info["number_of_packets"]))

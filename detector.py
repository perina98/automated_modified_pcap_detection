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

import multiprocessing

from modules import checksums, protocols, arp, macs, db, responses, app_layer
from modules.db import Pcap, Packet
from static import constants
from scapy.all import *
from scapy.layers.tls import *

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import StaticPool

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Detector():
    def __init__(self):
        self.pcaps = None
        self.args = self.get_args()
        self.db = db.Database()
        self.checksums = checksums.Checksums()

        logging.basicConfig(level=self.args.log.upper(), format='%(message)s')
        self.log = logging.getLogger(__name__)

        load_layer('tls')
        self.log.debug("Ensuring database exists")

        engine = create_engine('sqlite:///' + constants.DATABASE)
        self.db.ensure_db(engine, constants.DATABASE)

    def run(self):
        engine = create_engine('sqlite:///' + constants.DATABASE)
        session = sessionmaker(bind=engine)()
        if self.args.dataset_dir:
            pcaps = self.get_dataset_pcaps()
            for pcap in pcaps:
                id_pcap = self.db.save_pcap(session, pcap)
                self.check_pcap(pcap, id_pcap)
            exit(0)

        if self.args.input_pcap:
            if not self.args.input_pcap.endswith(".pcap"):
                print('Input file is not pcap')
                exit(1)
            id_pcap = self.db.save_pcap(session, self.args.input_pcap)
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

    def process_packet(self, packet):
        pcap_modifications = {
            'failed_checksums': 0,
            'failed_protocols': 0,
        } 
        if self.checksums.check_checksum(packet):
            pcap_modifications["failed_checksums"] += 1
        if protocols.Protocols().check_protocol(packet):
            pcap_modifications["failed_protocols"] += 1

        return pcap_modifications
        
    def save_packets(self, packet_chunk, id_pcap):
        engine = create_engine('sqlite:///' + constants.DATABASE)
        session = sessionmaker(bind=engine)()
        for packet in packet_chunk:
            self.db.save_packet(session, id_pcap, packet)
        
        session.commit()

    def worker(self, in_queue, save_queue, shared_list, worker_type, id_pcap):
        if worker_type == 'process':
            while True:
                packet = in_queue.get()
                if packet is None:
                    in_queue.task_done()
                    break

                processed_packet = self.process_packet(packet)
                shared_list.append(processed_packet)
                in_queue.task_done()
        elif worker_type == 'save':
            packet_chunk = []
            while True:
                packet = save_queue.get()
                if packet is None:
                    save_queue.task_done()
                    self.save_packets(packet_chunk, id_pcap)
                    break
                save_queue.task_done()

                packet_chunk.append(packet)

                if len(packet_chunk) == 1000:
                    self.save_packets(packet_chunk, id_pcap)
                    packet_chunk = []


    # read pcap file and check if it is modified
    def check_pcap(self, pcap_path, id_pcap):
        packet_count = self.get_pcap_packets_count(self.args.input_pcap)

        pcap_modifications = {
            'failed_checksums': 0,
            'failed_protocols': 0,
            'failed_arp_ips': 0,
            'failed_macs_map': 0,
            'failed_response_times': 0,
            'failed_dns_query_answer': 0,
            'failed_dns_answer_time': 0,
        }

        in_queue = multiprocessing.JoinableQueue()
        save_queue = multiprocessing.JoinableQueue()
        manager = multiprocessing.Manager()
        shared_list = manager.list([])

        num_processes = multiprocessing.cpu_count() - 1
        workers = []
        for i in range(num_processes):
            p = multiprocessing.Process(target=self.worker, args=(in_queue, save_queue, shared_list, 'process', id_pcap))
            workers.append(p)
            p.start()
        p = multiprocessing.Process(target=self.worker, args=(in_queue, save_queue, shared_list, 'save', id_pcap))
        workers.append(p)
        p.start()

        pkts = PcapReader(pcap_path)
        for packet in pkts:
            in_queue.put(packet)
            save_queue.put(packet)

        for i in range(num_processes):
            in_queue.put(None)
        save_queue.put(None)

        for p in workers:
            p.join()

        for packet in shared_list:
            for key in packet:
                pcap_modifications[key] += packet[key]

        engine = create_engine('sqlite:///' + constants.DATABASE)
        session = sessionmaker(bind=engine)()

        pcap_modifications["failed_arp_ips"] = arp.Arp().get_failed_arp_ips(id_pcap, session)
        pcap_modifications["failed_macs_map"] = macs.Macs().get_failed_mac_maps(id_pcap, session)
        pcap_modifications["failed_response_times"] = responses.Responses().get_failed_response_times(id_pcap, session)
        pcap_modifications["failed_dns_query_answer"] = app_layer.AppLayer().get_failed_dns_query_answer(id_pcap, session)
        pcap_modifications["failed_dns_answer_time"] = app_layer.AppLayer().get_failed_dns_answer_time(id_pcap, session)


        print (pcap_path," pcap_modifications['failed_checksums'] = ", str(pcap_modifications["failed_checksums"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_protocols'] = ", str(pcap_modifications["failed_protocols"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_arp_ips'] = ", str(pcap_modifications["failed_arp_ips"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_macs_map'] = ", str(pcap_modifications["failed_macs_map"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_response_times'] = ", str(pcap_modifications["failed_response_times"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_dns_query_answer'] = ", str(pcap_modifications["failed_dns_query_answer"]) + "/" + str(packet_count))
        print (pcap_path," pcap_modifications['failed_dns_answer_time'] = ", str(pcap_modifications["failed_dns_answer_time"]) + "/" + str(packet_count))

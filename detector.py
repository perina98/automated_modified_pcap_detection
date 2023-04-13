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

import os
import logging

import multiprocessing

from modules import checksums, protocols, db, responses, app_layer, datalink_layer
from static import constants
from scapy.all import *
from scapy.layers.tls import *

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Detector():
    def __init__(self, args=None):
        '''
        Initialize the detector
        Args:

        Returns:
        '''
        self.args = args
        self.db = db.Database()

        logging.basicConfig(level=self.args.log.upper(), format='%(message)s')
        self.log = logging.getLogger(__name__)

        load_layer('tls')
        self.log.debug("Ensuring database exists")

        engine = create_engine(constants.ENGINE + ':///' + constants.DATABASE)
        self.db.ensure_db(engine, constants.DATABASE)

    def run(self):
        '''
        Run the detector, either on dataset or on single pcap file
        Args:

        Returns:
        '''
        engine = create_engine(constants.ENGINE + ':///' + constants.DATABASE)
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
        '''
        Get number of packets in pcap file
        Using capinfos from tshark
        Args:
            pcap_path (str): Path to pcap file

        Returns:
            int: Number of packets in pcap file
        '''
        num = os.popen("capinfos -c -M " + pcap_path + " | grep -oP \"\s{3}\d+\"").read()
        if num == '':
            return 0
        return int(num)

    def get_dataset_pcaps(self):
        '''
        Get all pcaps from dataset directory
        Args:

        Returns:
            list: List of pcap paths
        '''
        pcaps = []
        self.log.debug("Getting pcaps from dataset directory")
        for file in os.listdir(self.args.dataset_dir):
            if file.endswith(".pcap"):
                pcaps.append(self.args.dataset_dir+'/'+file)
        self.log.debug("Found " + str(len(pcaps)) + " pcaps")
        return pcaps

    def process_packet(self, packet, checksum_mod, protocol_mod):
        '''
        Process packet and check for modifications
        Args:
            packet (scapy packet): Packet to process
            checksum_mod (Checksums): Checksums module
            protocol_mod (Protocols): Protocols module

        Returns:
            dict: Dictionary of modifications
        '''
        pcap_modifications = {
            'failed_checksums': 0,
            'failed_protocols': 0,
        } 
        
        if checksum_mod.check_checksum(packet):
            pcap_modifications["failed_checksums"] += 1
        if protocol_mod.check_protocol(packet):
            pcap_modifications["failed_protocols"] += 1

        return pcap_modifications
        
    def save_packets(self, packet_chunk, id_pcap):
        '''
        Save packets to database
        Args:
            packet_chunk (list): List of packets to save
            id_pcap (int): Id of pcap file

        Returns:
        '''
        engine = create_engine(constants.ENGINE + ':///' + constants.DATABASE)
        session = sessionmaker(bind=engine)()
        for packet in packet_chunk:
            self.db.save_packet(session, id_pcap, packet)
        
        session.commit()

    def process_worker(self, in_queue, shared_list):
        '''
        Process packets in queue
        Args:
            in_queue (multiprocessing queue): Queue with packets to process
            shared_list (list): List of processed packets

        Returns:
        '''
        checksum_mod = checksums.Checksums()
        protocol_mod = protocols.Protocols()
        while True:
            packet = in_queue.get()
            if packet is None:
                in_queue.task_done()
                break

            processed_packet = self.process_packet(packet, checksum_mod, protocol_mod)
            shared_list.append(processed_packet)
            in_queue.task_done()

    def save_worker(self, save_queue, id_pcap):
        '''
        Save packets in queue
        Args:
            save_queue (multiprocessing queue): Queue with packets to save
            id_pcap (int): Id of pcap file

        Returns:
        '''
        packet_chunk = []
        while True:
            packet = save_queue.get()
            if packet is None:
                save_queue.task_done()
                self.save_packets(packet_chunk, id_pcap)
                break
            save_queue.task_done()

            packet_chunk.append(packet)

            if len(packet_chunk) == constants.SAVE_CHUNK_SIZE:
                self.log.debug("Saving packets of chunk size " + str(constants.SAVE_CHUNK_SIZE))
                self.save_packets(packet_chunk, id_pcap)
                packet_chunk = []

    def print_results(self, pcap_path, packet_count, pcap_modifications):
        '''
        Print results of pcap file
        Args:
            pcap_path (str): Path to pcap file
            packet_count (int): Number of packets in pcap file
            pcap_modifications (dict): Dictionary of modifications

        Returns:
        '''
        keys = pcap_modifications.keys()

        for key in keys:
            print (pcap_path," pcap_modifications['"+key+"'] = ", str(pcap_modifications[key]) + "/" + str(packet_count))

    # read pcap file and check if it is modified
    def check_pcap(self, pcap_path, id_pcap):
        '''
        Check pcap file for modifications
        Args:
            pcap_path (str): Path to pcap file
            id_pcap (int): Id of pcap file

        Returns:
        '''
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

        
        manager = multiprocessing.Manager()
        shared_list = manager.list([])

        self.manage_multiprocessing(pcap_path, id_pcap, shared_list)

        self.log.debug("Accumulating results")
        for packet in shared_list:
            for key in packet:
                pcap_modifications[key] += packet[key]

        engine = create_engine(constants.ENGINE + ':///' + constants.DATABASE)
        session = sessionmaker(bind=engine)()

        app_layer_mod = app_layer.AppLayer(id_pcap, session)
        datalink_layer_mod = datalink_layer.DataLinkLayer(id_pcap, session)

        # run datalink layer tests
        self.log.debug("Running data link layer tests")
        pcap_modifications["failed_arp_ips"] = datalink_layer_mod.get_failed_arp_ips()
        pcap_modifications["failed_macs_map"] = datalink_layer_mod.get_failed_mac_maps()

        # run app layer tests
        self.log.debug("Running app layer tests")
        pcap_modifications["failed_dns_query_answer"] = app_layer_mod.get_failed_dns_query_answer()
        pcap_modifications["failed_dns_answer_time"] = app_layer_mod.get_failed_dns_answer_time()


        # run response times tests
        pcap_modifications["failed_response_times"] = responses.Responses().get_failed_response_times(id_pcap, session)

        self.print_results(pcap_path, packet_count, pcap_modifications)

    def manage_multiprocessing(self, pcap_path, id_pcap, shared_list):
        '''
        Manage multiprocessing
        Args:
            pcap_path (str): Path to pcap file
            id_pcap (int): Id of pcap file
            shared_list (list): List of processed packets

        Returns:
        '''

        '''
        Create queues and processes
        Start n-1 process workers and 1 save worker
        '''
        in_queue = multiprocessing.JoinableQueue()
        save_queue = multiprocessing.JoinableQueue()
        num_processes = multiprocessing.cpu_count() - 1
        workers = []
        for i in range(num_processes):
            process = multiprocessing.Process(target=self.process_worker, args=(in_queue, shared_list))
            workers.append(process)
            self.log.debug("Starting process worker %d", i)
            process.start()

        process = multiprocessing.Process(target=self.save_worker, args=(save_queue, id_pcap))
        workers.append(process)
        self.log.debug("Starting save worker")
        process.start()

        self.log.debug("Reading pcap file and putting packets in queues")
        pkts = PcapReader(pcap_path)
        for packet in pkts:
            in_queue.put(packet)
            save_queue.put(packet)
        
        '''
        Put None in queues to signal workers to finish
        '''
        for i in range(num_processes):
            in_queue.put(None)
        save_queue.put(None)

        self.log.debug("Waiting for workers to finish")
        for process in workers:
            process.join()

    
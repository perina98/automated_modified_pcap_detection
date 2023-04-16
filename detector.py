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

from modules import link_layer, internet_layer, transport_layer, application_layer, misc, db
from static import constants
from scapy.all import *
from scapy.layers.tls import *

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Detector():
    '''
    Main detector class that handles the logic and calls other modules
    Args:

    Returns:
    '''
    def __init__(self, args=None):
        '''
        Initialize the detector
        Initialize database, logging and load layers
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
        Creates session, saves pcap info to database and calls check_pcap function
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
        Get number of packets in pcap file using capinfos from tshark
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

    def process_packet(self, packet, miscellaneous_mod):
        '''
        Process packet and check for modifications
        Args:
            packet (scapy packet): Packet to process
            checksum_mod (Checksums): Checksums module
            transport_layer_mod (Protocols): Protocols module

        Returns:
            dict: Dictionary of modifications
        '''
        pcap_modifications = {
            'failed_checksums': int(miscellaneous_mod.check_checksum(packet)),
            'failed_protocols': int(miscellaneous_mod.check_protocol(packet)),
        } 
        
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
        miscellaneous_mod = misc.Miscellaneous()
        while True:
            packet = in_queue.get()
            if packet is None:
                in_queue.task_done()
                break

            processed_packet = self.process_packet(packet, miscellaneous_mod)
            shared_list.append(processed_packet)
            in_queue.task_done()

    def save_worker(self, save_queue, id_pcap):
        '''
        Save packets in queue for each chunk size of SAVE_CHUNK_SIZE packets
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
                self.log.debug("Saving packets of chunk size " + str(len(packet_chunk)))
                self.save_packets(packet_chunk, id_pcap)
                packet_chunk = []

    def run_processes(self, pcap_path, id_pcap, shared_list):
        '''
        Manage multiprocessing, start processes and initialize queues

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

        self.log.debug("Detected %d cpus", multiprocessing.cpu_count())

        workers = []
        for i in range(num_processes):
            process = multiprocessing.Process(target=self.process_worker, args=(in_queue, shared_list))
            workers.append(process)
            self.log.debug("Starting process worker %d", i + 1)
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

    # read pcap file and check if it is modified
    def check_pcap(self, pcap_path, id_pcap):
        '''
        Check pcap file for modifications
        Args:
            pcap_path (str): Path to pcap file
            id_pcap (int): Id of pcap file

        Returns:
        '''
        packet_count = self.get_pcap_packets_count(pcap_path)

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

        self.run_processes(pcap_path, id_pcap, shared_list)

        self.log.debug("Accumulating results")
        for packet in shared_list:
            for key in packet:
                pcap_modifications[key] += packet[key]

        engine = create_engine(constants.ENGINE + ':///' + constants.DATABASE)
        session = sessionmaker(bind=engine)()

        link_layer_mod = link_layer.LinkLayer(id_pcap, session)
        internet_layer_mod = internet_layer.InternetLayer(id_pcap, session)
        transport_layer_mod = transport_layer.TransportLayer(id_pcap, session)
        application_layer_mod = application_layer.ApplicationLayer(id_pcap, session)

        self.log.debug("Running link layer tests")
        pcap_modifications["failed_arp_ips"] = link_layer_mod.get_failed_arp_ips()
        pcap_modifications["failed_macs_map"] = link_layer_mod.get_failed_mac_maps()

        self.log.debug("Running app layer tests")
        pcap_modifications["failed_dns_query_answer"] = application_layer_mod.get_failed_dns_query_answer()
        pcap_modifications["failed_dns_answer_time"] = application_layer_mod.get_failed_dns_answer_time()

        self.log.debug("Running response times tests")
        pcap_modifications["failed_response_times"] = transport_layer_mod.get_failed_response_times()

        self.print_results(pcap_path, packet_count, pcap_modifications)

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

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
import re
import yaml

import multiprocessing

from modules import link_layer, internet_layer, transport_layer, application_layer, misc, pcapdata, db
from scapy.all import *
from scapy.layers.tls import *

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Detector():
    '''
    Main detector class that handles the logic and calls other modules
    '''
    def __init__(self, args=None):
        '''
        Initialize the detector
        Initialize database, logging and load layers
        Args:

        Returns:
            None
        '''
        self.args = args
        self.db = db.Database()

        with open(self.args.config, 'r') as f:
            self.config = yaml.safe_load(f)

        logging.basicConfig(level=self.args.log.upper(), format='%(message)s')
        self.log = logging.getLogger(__name__)

        load_layer('tls')

        self.log.debug("Ensuring database exists")

        engine = create_engine(self.config['database']['engine'] + ':///' + self.config['database']['file'])
        self.db.ensure_db(engine, self.config['database']['file'])

    def run(self):
        '''
        Run the detector, either on dataset or on single pcap file
        Creates session, saves pcap info to database and calls check_pcap function
        Args:

        Returns:
            None
        '''
        engine = create_engine(self.config['database']['engine'] + ':///' + self.config['database']['file'])
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

    def get_snaplenlimit(self, s):
        '''
        Get snap len limit from packet header
        Args:
            s: string to parse

        Returns:
            snaplenlimit: snap len limit
        '''
        if 'range' in s:
            match = re.search(r'\d+ bytes - (\d+) bytes \(range\)', s)
            if match:
                return int(match.group(1))
        else:
            match = re.search(r'(\d+) bytes', s)
            if match:
                return int(match.group(1))
        return None
    
    def get_capinfos_data(self, pcap_path):
        '''
        Get pcap header data using capinfos
        Args:
            pcap_path: path to pcap file

        Returns:
            dict: pcap header data
        '''
        self.log.debug("Getting pcap header data")
        cmd = ['capinfos', '-M', pcap_path]
        output = subprocess.check_output(cmd, universal_newlines=True)
        lines = output.strip().split('\n')
        data = {}
        data['snaplenlimit'] = 0
        for line in lines:
            match = re.match(r'^(.*?):\s+(.*)$', line)
            if match:
                key = match.group(1)
                value = match.group(2)
                if key == 'Packet size limit':
                    data['snaplenlimit'] = self.get_snaplenlimit(value)
                data[key] = value

        data['File size'] = int(data['File size'].replace(' bytes', ''))
        data['Data size'] = int(data['Data size'].replace(' bytes', ''))

        return data

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
        if not self.config['tests']['misc']:
            return {}
        
        packet_modifications = {
            'mismatched_checksums': int(miscellaneous_mod.check_checksum(packet)),
            'mismatched_protocols': int(miscellaneous_mod.check_protocol(packet)),
            'incorrect_packet_length': int(miscellaneous_mod.check_packet_length(packet)),
            'invalid_packet_payload': int(miscellaneous_mod.check_invalid_payload(packet)),
            'insuficient_capture_length': int(miscellaneous_mod.check_frame_len_and_cap_len(packet)),
        } 

        return packet_modifications
        
    def save_packets(self, packet_chunk, id_pcap):
        '''
        Save packets to database
        Args:
            packet_chunk (list): List of packets to save
            id_pcap (int): Id of pcap file

        Returns:
            None
        '''
        engine = create_engine(self.config['database']['engine'] + ':///' + self.config['database']['file'])
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
            None
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
        Save packets in queue for each chunk size of self.config['app']['chunk_size'] packets
        Args:
            save_queue (multiprocessing queue): Queue with packets to save
            id_pcap (int): Id of pcap file

        Returns:
            None
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

            if len(packet_chunk) == self.config['app']['chunk_size']:
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
            None
        '''

        # Create queues and processes
        in_queue = multiprocessing.JoinableQueue()
        save_queue = multiprocessing.JoinableQueue()
        num_processes = multiprocessing.cpu_count() - 1

        self.log.debug("Detected %d cpus", multiprocessing.cpu_count())

        workers = []
        # Start process workers
        for i in range(num_processes):
            process = multiprocessing.Process(target=self.process_worker, args=(in_queue, shared_list))
            workers.append(process)
            self.log.debug("Starting process worker %d", i + 1)
            process.start()

        # Start save worker
        process = multiprocessing.Process(target=self.save_worker, args=(save_queue, id_pcap))
        workers.append(process)
        self.log.debug("Starting save worker")
        process.start()

        self.log.debug("Reading pcap file and putting packets in queues")
        pkts = PcapReader(pcap_path)
        for packet in pkts:
            in_queue.put(packet)
            save_queue.put(packet)
        
        # Put None in queues to signal workers to finish
        for i in range(num_processes):
            in_queue.put(None)
        save_queue.put(None)

        self.log.debug("Waiting for workers to finish")
        for process in workers:
            process.join()

    def check_pcap(self, pcap_path, id_pcap):
        '''
        Check pcap file for modifications
        Args:
            pcap_path (str): Path to pcap file
            id_pcap (int): Id of pcap file

        Returns:
            None
        '''
        capinfos = self.get_capinfos_data(pcap_path)

        packet_count = capinfos['Number of packets']
        pcap_snaplen_limit = capinfos['snaplenlimit']
        pcap_file_size = capinfos['File size']
        pcap_data_size = capinfos['Data size']

        packet_modifications = {
            'mismatched_checksums': 0,
            'mismatched_protocols': 0,
            'incorrect_packet_length': 0,
            'missing_arp_traffic': 0,
            'inconsistent_mac_maps': 0,
            'inconsistent_interpacket_gaps': 0,
            'mismatched_dns_query_answer': 0,
            'mismatched_dns_answer_stack': 0,
            'missing_translation_of_visited_domain': 0,
            'translation_of_unvisited_domains': 0,
            'incomplete_ftp': 0,
            'invalid_packet_payload': 0,
            'missing_arp_responses': 0,
            'insuficient_capture_length': 0,
            'inconsistent_ttls': 0,
            'inconsistent_mss': 0,
            'inconsistent_window_size': 0,
            'mismatched_ciphers': 0,
            'incomplete_tcp_streams': 0,
            'missing_dhcp_ips': 0,
            'missing_icmp_ips': 0,
            'inconsistent_user_agent': 0,
            'inconsistent_fragmentation': 0,
        }

        pcap_modifications = {
            'snaplen_context': False,
            'file_and_data_size': False,
        }

        manager = multiprocessing.Manager()
        shared_list = manager.list([])

        self.run_processes(pcap_path, id_pcap, shared_list)

        self.log.debug("Accumulating results")
        for packet in shared_list:
            for key in packet:
                packet_modifications[key] += packet[key]

        engine = create_engine(self.config['database']['engine'] + ':///' + self.config['database']['file'])
        session = sessionmaker(bind=engine)()

        if self.config['tests']['pcap']:
            self.log.debug("Running pcap modification tests")
            pcapdata_mod = pcapdata.PcapData(id_pcap, session)
            pcap_modifications["snaplen_context"] = pcapdata_mod.check_snaplen_context(pcap_snaplen_limit)
            pcap_modifications["file_and_data_size"] = pcapdata_mod.check_file_data_size(pcap_file_size, pcap_data_size)

        self.log.debug("Running packet modification tests")

        if self.config['tests']['link_layer']:
            self.log.debug("Running link layer tests")
            link_layer_mod = link_layer.LinkLayer(id_pcap, session)
            packet_modifications["missing_arp_traffic"] = link_layer_mod.get_missing_arp_traffic()
            packet_modifications["inconsistent_mac_maps"] = link_layer_mod.get_inconsistent_mac_maps()
            packet_modifications["lost_arp_traffic"] = link_layer_mod.get_lost_traffic_by_arp()
            packet_modifications["missing_arp_responses"] = link_layer_mod.get_missing_arp_responses()

        if self.config['tests']['internet_layer']:
            self.log.debug("Running internet layer tests")
            internet_layer_mod = internet_layer.InternetLayer(id_pcap, session)
            packet_modifications["inconsistent_ttls"] = internet_layer_mod.get_inconsistent_ttls()
            packet_modifications["inconsistent_fragmentation"] = internet_layer_mod.get_inconsistent_fragmentation()

        if self.config['tests']['transport_layer']:
            self.log.debug("Running transport layer tests")
            transport_layer_mod = transport_layer.TransportLayer(id_pcap, session)
            packet_modifications["inconsistent_interpacket_gaps"] = transport_layer_mod.get_inconsistent_interpacket_gaps()
            packet_modifications["inconsistent_mss"] = transport_layer_mod.get_inconsistent_mss()
            # packet_modifications["inconsistent_window_size"] = transport_layer_mod.get_inconsistent_window()
            packet_modifications["mismatched_ciphers"] = transport_layer_mod.get_mismatched_ciphers()
            packet_modifications["incomplete_tcp_streams"] = transport_layer_mod.get_incomplete_tcp_streams()

        if self.config['tests']['application_layer']:
            self.log.debug("Running app layer tests")
            application_layer_mod = application_layer.ApplicationLayer(id_pcap, session)
            packet_modifications["mismatched_dns_query_answer"] = application_layer_mod.get_mismatched_dns_query_answer()
            packet_modifications["mismatched_dns_answer_stack"] = application_layer_mod.get_mismatched_dns_answer_stack()
            packet_modifications["missing_translation_of_visited_domain"] = application_layer_mod.get_missing_translation_of_visited_domain()
            packet_modifications["translation_of_unvisited_domains"] = application_layer_mod.get_translation_of_unvisited_domains()
            packet_modifications["incomplete_ftp"] = application_layer_mod.get_incomplete_ftp()
            packet_modifications["missing_dhcp_ips"] = application_layer_mod.get_missing_dhcp_ips()
            packet_modifications["missing_icmp_ips"] = application_layer_mod.get_missing_icmp_ips()
            packet_modifications["inconsistent_user_agent"] = application_layer_mod.get_inconsistent_user_agent()


        self.print_results(pcap_path, packet_count, pcap_modifications, packet_modifications)

    def print_results(self, pcap_path, packet_count, pcap_modifications, packet_modifications):
        '''
        Print results of pcap file
        Args:
            pcap_path (str): Path to pcap file
            packet_count (int): Number of packets in pcap file
            pcap_modifications (dict): Dictionary of modifications
            packet_modifications (dict): Dictionary of modifications

        Returns:
            None
        '''
        pcap_keys = pcap_modifications.keys()
        packet_keys = packet_modifications.keys()

        print ("")
        print ("=== Results ===")
        print ("")

        print("Pcap modifications:")
        for key in pcap_keys:
            if pcap_modifications[key]:
                print (pcap_path," pcap_modifications['"+key+"'] = ", "Modified")
            else:
                print (pcap_path," pcap_modifications['"+key+"'] = ", "Not modified")

        print("Packet modifications:")
        for key in packet_keys:
            print (pcap_path," packet_modifications['"+key+"'] = ", str(packet_modifications[key]) + "/" + str(packet_count))

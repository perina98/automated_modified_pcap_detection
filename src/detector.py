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
from tqdm import tqdm

from . import statistics
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
        self.file_start_time = 0
        self.start_time = 0
        self.db = db.Database()

        with open(self.args.config, 'r') as f:
            self.config = yaml.safe_load(f)

        logging.basicConfig(level=self.args.log.upper(), format='%(message)s')
        self.log = logging.getLogger(__name__)

        if self.args.filelog:
            # turn on logging into log.log file, clear the file if it exists
            open('log.log', 'w').close()
            fh = logging.FileHandler('log.log')
            fh.setLevel(logging.DEBUG)
            self.log.addHandler(fh)

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
                if not os.path.exists(pcap):
                    print('Input file does not exist')
                    exit(1)
                self.log.info("Processing pcap: " + pcap)
                self.file_start_time = time.time()
                id_pcap = self.db.save_pcap(session, pcap)
                self.check_pcap(pcap, id_pcap)
            exit(0)

        if self.args.input_pcap:
            if not self.args.input_pcap.endswith(".pcap"):
                print('Input file is not pcap')
                exit(1)
            if not os.path.exists(self.args.input_pcap):
                print('Input file does not exist')
                exit(1)
            self.log.info("Processing pcap: " + self.args.input_pcap)
            self.file_start_time = time.time()
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
        return 1000000
    
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
        result = subprocess.run(cmd, universal_newlines=True, capture_output=True, text=True)
        exit_code = result.returncode
        if exit_code != 0:
            self.log.error("Error while getting pcap header data. Pcap file might be corrupted.")
            exit(1)
        output = result.stdout
        exit_code = 0
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
        if not os.path.exists(self.args.dataset_dir):
            print('Dataset directory does not exist')
            exit(1)
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
            'mismatched_protocols': int(miscellaneous_mod.check_ports(packet)),
            'incorrect_packet_length': int(miscellaneous_mod.check_packet_length(packet)),
            'invalid_packet_payload': int(miscellaneous_mod.check_invalid_payload(packet)),
            'insuficient_capture_length': int(miscellaneous_mod.check_frame_len_and_cap_len(packet)),
            'mismatched_ntp_timestamp': int(miscellaneous_mod.check_mismatched_ntp_timestamp(packet)),
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
        session.bind.dispose()
        session.close()
        engine.dispose()

    def process_worker(self, in_queue, shared_list):
        '''
        Process packets in queue
        Args:
            in_queue (multiprocessing queue): Queue with packets to process
            shared_list (list): List of processed packets

        Returns:
            None
        '''
        miscellaneous_mod = misc.Miscellaneous(self.config)
        while True:
            packet = in_queue.get()
            if packet is None:
                in_queue.task_done()
                break

            processed_packet = self.process_packet(packet, miscellaneous_mod)
            shared_list.append(processed_packet)
            in_queue.task_done()

            # WIP
            if False and len(shared_list) >= self.config['app']['chunk_size'] * self.config['app']['buffer_multiplier']:
                packet_modifications = {
                    'mismatched_checksums': 0,
                    'mismatched_protocols': 0,
                    'incorrect_packet_length': 0,
                    'invalid_packet_payload': 0,
                    'insuficient_capture_length': 0,
                    'mismatched_ntp_timestamp': 0,
                }

                for p in shared_list:
                    for key in packet_modifications:
                        packet_modifications[key] += p[key]
                
                shared_list = []
                shared_list.append(packet_modifications)

    def save_worker(self, save_queue, id_pcap, packet_count):
        '''
        Save packets in queue for each chunk size of self.config['app']['chunk_size'] packets
        Args:
            save_queue (multiprocessing queue): Queue with packets to save
            id_pcap (int): Id of pcap file

        Returns:
            None
        '''
        packet_chunk = []
        self.start_time = time.time()
        packets_processed = 0
        while True:
            packet = save_queue.get()
            if packet is None:
                save_queue.task_done()
                length_of_chunk = len(packet_chunk)
                if length_of_chunk > 0:
                    packets_processed += length_of_chunk
                    self.print_time_remaining(packet_count, packets_processed)
                    self.save_packets(packet_chunk, id_pcap)
                break

            save_queue.task_done()

            packet_chunk.append(packet)

            length_of_chunk = len(packet_chunk)

            if length_of_chunk == self.config['app']['chunk_size']:
                packets_processed += length_of_chunk
                self.save_packets(packet_chunk, id_pcap)
                self.print_time_remaining(packet_count, packets_processed)

                packet_chunk = []

    def print_time_remaining(self, packet_count, packets_processed):
        '''
        Print time remaining to finish processing packets
        Args:
            packet_count (int): Total number of packets
            packets_processed (int): Number of packets processed
            length_of_chunk (int): Length of chunk of packets

        Returns:
            None
        '''
        total_time_elapsed = time.time() - self.start_time
        packets_per_second = packets_processed / total_time_elapsed
        time_remaining = (packet_count - packets_processed) / packets_per_second

        time_units = [('seconds', 60), ('minutes', 60), ('hours', 24)]
        unit = ''
        for u, multiplier in time_units:
            if time_remaining < multiplier:
                unit = u
                break
            time_remaining /= multiplier

        self.log.info(f"Processed {packets_processed} / {packet_count} packets. Est. time remaining: {time_remaining:.2f} {unit}")

    def run_processes(self, pcap_path, id_pcap, shared_list, packet_count):
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
        in_queue = multiprocessing.JoinableQueue(maxsize=self.config['app']['chunk_size'] * self.config['app']['buffer_multiplier'])
        save_queue = multiprocessing.JoinableQueue(maxsize=self.config['app']['chunk_size'] * self.config['app']['buffer_multiplier'])
        num_processes = multiprocessing.cpu_count() - 1

        if self.config['app']['workers'] is not None:
            num_processes = self.config['app']['workers'] - 1

        self.log.debug("Detected %d cpus", multiprocessing.cpu_count())

        workers = []
        # Start process workers
        for i in range(num_processes):
            process = multiprocessing.Process(target=self.process_worker, args=(in_queue, shared_list))
            workers.append(process)
            self.log.debug("Starting process worker %d", i + 1)
            process.start()

        # Start save worker
        process = multiprocessing.Process(target=self.save_worker, args=(save_queue, id_pcap, packet_count))
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

    def init_modifications(self):
        '''
        Initialize modification dictionaries
        Args:

        Returns:
            None
        '''
        pcap_modifications = {
            'snaplen_context': False,
            'file_and_data_size': False,
        }

        packet_modifications = {
            'mismatched_checksums': 0,
            'mismatched_protocols': 0,
            'incorrect_packet_length': 0,
            'invalid_packet_payload': 0,
            'insuficient_capture_length': 0,
            'mismatched_ntp_timestamp': 0,

            'missing_arp_traffic': {'failed': 0, 'total': 0},
            'inconsistent_mac_maps': {'failed': 0, 'total': 0},
            'lost_arp_traffic': {'failed': 0, 'total': 0},
            'missing_arp_responses': {'failed': 0, 'total': 0},

            'inconsistent_ttls': {'failed': 0, 'total': 0},
            'inconsistent_fragmentation': {'failed': 0, 'total': 0},
            'sudden_drops_for_ip_source': {'failed': 0, 'total': 0},

            'inconsistent_interpacket_gaps': {'failed': 0, 'total': 0},
            'incomplete_tcp_streams': {'failed': 0, 'total': 0},
            'inconsistent_mss': {'failed': 0, 'total': 0},
            'inconsistent_window_size': {'failed': 0, 'total': 0},
            'mismatched_ciphers': {'failed': 0, 'total': 0},

            'mismatched_dns_query_answer': {'failed': 0, 'total': 0},
            'mismatched_dns_answer_stack': {'failed': 0, 'total': 0},
            'missing_translation_of_visited_domain': {'failed': 0, 'total': 0},
            'translation_of_unvisited_domains': {'failed': 0, 'total': 0},
            'incomplete_ftp': {'failed': 0, 'total': 0},
            'missing_dhcp_ips': {'failed': 0, 'total': 0},
            'missing_icmp_ips': {'failed': 0, 'total': 0},
            'inconsistent_user_agent': {'failed': 0, 'total': 0},
        }

        return pcap_modifications, packet_modifications

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

        packet_count = int(capinfos['Number of packets'])
        pcap_snaplen_limit = int(capinfos['snaplenlimit'])
        pcap_file_size = capinfos['File size']
        pcap_data_size = capinfos['Data size']

        pcap_modifications, packet_modifications = self.init_modifications()

        manager = multiprocessing.Manager()
        shared_list = manager.list([])

        self.run_processes(pcap_path, id_pcap, shared_list, packet_count)

        # acumulate results
        for packet in tqdm(shared_list, desc="Accumulating results", unit="packets", total=packet_count):
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
            packet_modifications["missing_arp_traffic"]['failed'], packet_modifications["missing_arp_traffic"]['total'] = link_layer_mod.get_missing_arp_traffic()
            packet_modifications["inconsistent_mac_maps"]['failed'], packet_modifications["inconsistent_mac_maps"]['total'] = link_layer_mod.get_inconsistent_mac_maps()
            packet_modifications["lost_arp_traffic"]['failed'], packet_modifications["lost_arp_traffic"]['total'] = link_layer_mod.get_lost_traffic_by_arp()
            packet_modifications["missing_arp_responses"]['failed'], packet_modifications["missing_arp_responses"]['total'] = link_layer_mod.get_missing_arp_responses()

        if self.config['tests']['internet_layer']:
            self.log.debug("Running internet layer tests")
            internet_layer_mod = internet_layer.InternetLayer(self.config, id_pcap, session)
            packet_modifications["inconsistent_ttls"]['failed'], packet_modifications["inconsistent_ttls"]['total'] = internet_layer_mod.get_inconsistent_ttls()
            packet_modifications["inconsistent_fragmentation"]['failed'], packet_modifications["inconsistent_fragmentation"]['total'] = internet_layer_mod.get_inconsistent_fragmentation()
            packet_modifications["sudden_drops_for_ip_source"]['failed'], packet_modifications["sudden_drops_for_ip_source"]['total'] = internet_layer_mod.get_sudden_ip_source_traffic_drop()

        if self.config['tests']['transport_layer']:
            self.log.debug("Running transport layer tests")
            transport_layer_mod = transport_layer.TransportLayer(self.config, id_pcap, session)
            packet_modifications["inconsistent_interpacket_gaps"]['failed'], packet_modifications["inconsistent_interpacket_gaps"]['total'] = transport_layer_mod.get_inconsistent_interpacket_gaps()
            packet_modifications["incomplete_tcp_streams"]['failed'], packet_modifications["incomplete_tcp_streams"]['total'] = transport_layer_mod.get_incomplete_tcp_streams()
            packet_modifications["inconsistent_mss"]['failed'], packet_modifications["inconsistent_mss"]['total'] = transport_layer_mod.get_inconsistent_mss()
            packet_modifications["inconsistent_window_size"]['failed'], packet_modifications["inconsistent_window_size"]['total'] = transport_layer_mod.get_inconsistent_window()
            packet_modifications["mismatched_ciphers"]['failed'], packet_modifications["mismatched_ciphers"]['total'] = transport_layer_mod.get_mismatched_ciphers()

        if self.config['tests']['application_layer']:
            self.log.debug("Running application layer tests")
            application_layer_mod = application_layer.ApplicationLayer(self.config, id_pcap, session)
            packet_modifications["mismatched_dns_query_answer"]['failed'], packet_modifications["mismatched_dns_query_answer"]['total'] = application_layer_mod.get_mismatched_dns_query_answer()
            packet_modifications["mismatched_dns_answer_stack"]['failed'], packet_modifications["mismatched_dns_answer_stack"]['total'] = application_layer_mod.get_mismatched_dns_answer_stack()
            packet_modifications["missing_translation_of_visited_domain"]['failed'], packet_modifications["missing_translation_of_visited_domain"]['total'] = application_layer_mod.get_missing_translation_of_visited_domain()
            packet_modifications["translation_of_unvisited_domains"]['failed'], packet_modifications["translation_of_unvisited_domains"]['total'] = application_layer_mod.get_translation_of_unvisited_domains()
            packet_modifications["incomplete_ftp"]['failed'], packet_modifications["incomplete_ftp"]['total'] = application_layer_mod.get_incomplete_ftp()
            packet_modifications["missing_dhcp_ips"]['failed'], packet_modifications["missing_dhcp_ips"]['total'] = application_layer_mod.get_missing_dhcp_ips()
            packet_modifications["missing_icmp_ips"]['failed'], packet_modifications["missing_icmp_ips"]['total'] = application_layer_mod.get_missing_icmp_ips()
            packet_modifications["inconsistent_user_agent"]['failed'], packet_modifications["inconsistent_user_agent"]['total'] = application_layer_mod.get_inconsistent_user_agent()


        stats = statistics.Statistics(pcap_path, packet_count, pcap_modifications, packet_modifications, self.file_start_time, self.config['tests']['misc'])
        stats.print_results()

        if self.args.outputhtml:
            stats.generate_results_summary_file()

        if self.args.filelog:
            stats.log_results_to_file()

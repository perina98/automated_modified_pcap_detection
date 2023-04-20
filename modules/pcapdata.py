##################################################
## This module provides necessary functions for other modules
##################################################
## File: functions.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from database import Packet

class PcapData():
    '''
    Class that provides functions for other modules
    '''
    def __init__(self, id_pcap = None, session = None):
        '''
        Constructor
        Args:
            id_pcap (int): id of the pcap file in the database
            session (mixed): database session

        Returns:
            None
        '''
        self.id_pcap = id_pcap
        self.session = session
    
    def check_snaplen_context(self, pcap_snaplen_limit):
        '''
        Check if there are no diviations in the snaplen context
        Args:

        Returns:
            bool: True if there are no diviations in the snaplen context False otherwise
        '''
        packets = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        capture_context = {}

        plen = len(packets)

        for packet in packets:
            if packet.length > pcap_snaplen_limit:
                return True
            if packet.length not in capture_context:
                capture_context[packet.length] = 1
            else:
                capture_context[packet.length] += 1

        for key in capture_context:
            capture_context[key] = capture_context[key] / plen

        if max(capture_context.values()) > 0.5 and len(capture_context) > 1:
            return True
        
        return False
    

    def check_file_data_size(self, pcap_file_size, pcap_data_size):
        '''
        Check if the file size is smaller than data size
        Args:

        Returns:
            bool: True if the file size is smaller than data size False otherwise
        '''
        if pcap_file_size < pcap_data_size:
            return True
        
        return False
        
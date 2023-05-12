##################################################
## This module represents detection module for PCAP specific data
##################################################
## File: pcapdata.py
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
    Class that provides detection methods specific to PCAP files
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
        packets = self.session.query(Packet.length).filter(Packet.id_pcap == self.id_pcap).all()

        capture_context = {}

        plen = len(packets)

        # go over all packets and check if the length is bigger than snaplen limit
        for packet in packets:
            if packet.length > pcap_snaplen_limit:
                return True
            if packet.length not in capture_context:
                capture_context[packet.length] = 1
            else:
                capture_context[packet.length] += 1
            if len(capture_context) > (len(packets) / 2):
                return False

        # calculate relative frequency of each length
        for key in capture_context:
            capture_context[key] = capture_context[key] / plen


        # check if there is a length that is more than 50% of all packets
        # this could mean that the snaplen limit was not set correctly or that the packets were truncated
        if len(capture_context) > 0 and max(capture_context.values()) > 0.5:
            return True
        
        return False
    
    def check_file_data_size(self, pcap_file_size, pcap_data_size):
        '''
        Check if the file size is smaller than data size
        This would indicate that the packets were truncated or edited
        Args:

        Returns:
            bool: True if the file size is smaller than data size False otherwise
        '''
        if pcap_file_size < pcap_data_size:
            return True
        
        return False
        
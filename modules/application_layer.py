##################################################
## This module checks application layer for any inconsistencies
##################################################
## File: application_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from database import Packet
import modules.functions as functions

class ApplicationLayer():
    '''
    Class for checking application layer for any inconsistencies
    '''
    def __init__(self, id_pcap, session):
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
        self.functions =  functions.Functions(id_pcap, session)

    def get_failed_dns_query_answer(self):
        '''
        Check if there is any DNS packet with different query and response
        Args:

        Returns:
            int: number of failed DNS query and answer pairs
        '''
        pairs = self.functions.get_dns_pairs()
        failed = 0
        for pair in pairs:
            for an in pairs[pair]['answer']:
                if an['rrname'] != pairs[pair]['query']['qname']:
                    failed += 1
        return failed

    def get_failed_dns_answer_time(self):
        '''
        Check A and AAAA records and check if the IP address appreared before the pkt time
        This would indicate that the IP address was spoofed
        Args:

        Returns:
            int: number of failed DNS query and answer pairs
        '''
        pairs = self.functions.get_dns_pairs()

        # filter only A and AAAA records
        pairs = {k: v for k, v in pairs.items() if v['type'] == 1 or v['type'] == 28}

        ip_addresses = {}
        for pair in pairs:
            for an in pairs[pair]['answer']:
                if an['rdata'] not in ip_addresses:
                    ip_addresses[an['rdata']] = []
                ip_addresses[an['rdata']].append(pairs[pair]['time'])
                
        # get all packets from the pcap file
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        failed = 0

        for pkt in pkts:
            if self.functions.is_private_ip(pkt.ip_src) or self.functions.is_private_ip(pkt.ip_dst):
                continue
            if pkt.ip_src in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_src]):
                    failed += 1
            if pkt.ip_dst in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_dst]):
                    failed += 1

        return failed        


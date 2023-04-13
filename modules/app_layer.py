##################################################
## This modules checks application layer for any inconsistencies
##################################################
## File: app_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import json
from scapy.all import *
from modules.db import Packet
import ipaddress

class AppLayer():
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

    def get_ip_obj(self, ip_address):
        try:
            # Create an IPv4Address object from the IP address string
            return ipaddress.IPv4Address(ip_address)
        except ipaddress.AddressValueError:
            pass

        return None

    def is_private_ip(self, ip_address):
        # Create an IPv4Address object from the IP address string
        ip_obj = self.get_ip_obj(ip_address)

        if ip_obj is None:
            # The IP address is not valid IPv4
            return False
        
        return ip_obj.is_private

    def get_dns_packets(self):
        '''
        Get only the dns packets from sqlite database
        Args:

        Returns:
            list: list of packets
        '''
        return self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap, Packet.protocol == 17).all()

    def get_dns_pairs(self):
        '''
        Get DNS query and answer pairs from the pcap file
        Args:

        Returns:
            dict: dictionary of query and answer pairs
        '''
        pkts = self.get_dns_packets()
        pairs = {}

        for pkt in pkts:
            if pkt.dns:
                dns = json.loads(pkt.dns)
                if dns['id'] not in pairs:
                    pairs[dns['id']] = {}
                    pairs[dns['id']]['time'] = pkt.packet_timestamp
                if dns['an']:
                    pairs[dns['id']]['answer'] = dns['an']
                else:
                    pairs[dns['id']]['query'] = dns['qd']
                    pairs[dns['id']]['type'] = dns['qd']['qtype'] if dns['qd'] is not None else 0

        # filter only pairs with query and answer
        return {k: v for k, v in pairs.items() if 'query' in v and 'answer' in v}

    # check if there is any DNS packet with different query and response
    def get_failed_dns_query_answer(self):
        '''
        Check if there is any DNS packet with different query and response
        Args:

        Returns:
            int: number of failed DNS query and answer pairs
        '''
        pairs = self.get_dns_pairs()
        failed = 0
        for pair in pairs:
            for an in pairs[pair]['answer']:
                if an['rrname'] != pairs[pair]['query']['qname']:
                    failed += 1
        return failed

    # check A and AAAA records and check if the IP address appreared before the pkt time
    def get_failed_dns_answer_time(self):
        '''
        Check A and AAAA records and check if the IP address appreared before the pkt time
        This would indicate that the IP address was spoofed
        Args:

        Returns:
            int: number of failed DNS query and answer pairs
        '''
        pairs = self.get_dns_pairs()

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
            if self.is_private_ip(pkt.ip_src) or self.is_private_ip(pkt.ip_dst):
                continue
            if pkt.ip_src in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_src]):
                    failed += 1
            if pkt.ip_dst in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_dst]):
                    failed += 1

        return failed        

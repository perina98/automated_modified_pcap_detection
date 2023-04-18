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

import json
from scapy.all import *
from database import Packet
import ipaddress

class Functions():
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
        pass

    def is_private_ip(self, ip_addr):
        '''
        Check if the IP address is private
        Args:
            ip_addr (str): IP address

        Returns:
            None
        '''
        # Check if the IP address is valid
        try:
            ipaddress.ip_address(ip_addr)
        except ValueError:
            return False
        
        # Check if the IP address is private
        if ipaddress.ip_address(ip_addr).version == 4:
            private_ipv4_ranges = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16')
            ]
            for private_range in private_ipv4_ranges:
                if ipaddress.IPv4Address(ip_addr) in private_range:
                    return True
        elif ipaddress.ip_address(ip_addr).version == 6:
            private_ipv6_ranges = [
                ipaddress.IPv6Network('fc00::/7'),
                ipaddress.IPv6Network('fd00::/8'),
                ipaddress.IPv6Network('::/10')
            ]
            for private_range in private_ipv6_ranges:
                if ipaddress.IPv6Address(ip_addr) in private_range:
                    return True
        
        # If the IP address is not private for either IPv4 or IPv6, return False
        return False

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
                if dns['an']:
                    pairs[dns['id']]['answers'] = []
                    for answer in dns['an']:
                        a = {}
                        a['answer'] = answer
                        a['atype'] = answer['type']
                        a['atime'] = pkt.packet_timestamp
                        pairs[dns['id']]['answers'].append(a)
                    pairs[dns['id']]['answer_query'] = dns['qd']['qname'] if dns['qd'] is not None else ''
                else:
                    pairs[dns['id']]['query'] = dns['qd']
                    pairs[dns['id']]['qtype'] = dns['qd']['qtype'] if dns['qd'] is not None else 0
                    pairs[dns['id']]['qtime'] = pkt.packet_timestamp


        # filter only pairs with query and answer
        return {key: value for key, value in pairs.items() if 'query' in value and 'answers' in value}

    def get_macs(self):
        '''
        Get all MAC addresses and their IP addresses from the pcap file
        Args:

        Returns:
            dict: dictionary of MAC addresses and their IP addresses
        '''
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()
        macs = {}
        for pkt in pkts:
            if pkt.type == 2048:
                if macs.get(pkt.ip_src) == None:
                    macs[pkt.ip_src] = [pkt.eth_src]
                else:
                    macs[pkt.ip_src].append(pkt.eth_src)

                if macs.get(pkt.ip_dst) == None:
                    macs[pkt.ip_dst] = [pkt.eth_dst]
                else:
                    macs[pkt.ip_dst].append(pkt.eth_dst)

        return macs
    
    def get_arp_macs(self):
        '''
        Get all MAC addresses from ARP packets
        Args:

        Returns:
            set: set of MAC addresses
        '''
        arp_macs = []
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        for pkt in pkts:
            if pkt.type == 2054:
                arp_macs.append(pkt.eth_src)
                arp_macs.append(pkt.eth_dst)
                
        return set(arp_macs)
    
    def get_tcp_streams(self, pkts):
        '''
        Get TCP streams from the pcap file
        Args:
            pkts (list): list of packets

        Returns:
            None
        '''
        streams = {}
        for row in pkts:
            if row.type == 2048 and row.protocol == 6:
                key = (row.ip_src, row.ip_dst) if (row.ip_src, row.ip_dst) in streams else (row.ip_dst, row.ip_src)
                if key not in streams:
                    streams[key] = [row]
                else:
                    streams[key].append(row)
        return streams
    
    def get_protocols(self):
        '''
        Get all protocols from static files
        Args:

        Returns:
            None
        '''
        with open('static/TCPS.json') as f:
            TCPS = set(json.load(f))
        with open('static/UDPS.json') as f:
            UDPS = set(json.load(f))

        return {6: TCPS, 17: UDPS}
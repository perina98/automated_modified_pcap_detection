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
from sqlalchemy import and_

class Functions():
    '''
    Class that provides functions for other modules
    '''
    def __init__(self, id_pcap = None, session = None, config = None):
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
        self.config = config

    def is_private_ip(self, ip_addr):
        '''
        Check if the IP address is private
        Args:
            ip_addr (str): IP address

        Returns:
            bool: True if the IP address is private, False otherwise
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

            if self.config is not None and self.config['app']['custom_private_network'] is not None:
                try:
                    ipaddress.IPv4Network(self.config['app']['custom_private_network'])
                    private_ipv4_ranges.append(ipaddress.IPv4Network(self.config['app']['custom_private_network']))
                except ValueError:
                    pass

            for private_range in private_ipv4_ranges:
                if ipaddress.IPv4Address(ip_addr) in private_range:
                    return True
        elif ipaddress.ip_address(ip_addr).version == 6:
            private_ipv6_ranges = [
                ipaddress.IPv6Network('fc00::/7'),
                ipaddress.IPv6Network('fd00::/8'),
                ipaddress.IPv6Network('::/10')
            ]
            
            if self.config is not None and self.config['app']['custom_private_network'] is not None:
                try:
                    ipaddress.IPv6Network(self.config['app']['custom_private_network'])
                    private_ipv6_ranges.append(ipaddress.IPv6Network(self.config['app']['custom_private_network']))
                except ValueError:
                    pass

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
        return self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.protocol == 17
            )
        ).all()

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
    
    def find_synack(self, i, exp_ack, stream):
        '''
        Find syn ack packet in the stream
        Args:
            i (int): index of the packet in the stream
            exp_ack (int): expected ack number
            stream (list): list of packets
        Returns:
            Packet: syn ack packet if found, None otherwise
        '''
        for j in range(i, len(stream) - 1):
            if (stream[j].tcp_flags == 'SA' or stream[j].tcp_flags == 'SAE') and stream[j].ack == exp_ack:
                return stream[j]
        return None

    def get_macs(self):
        '''
        Get all MAC addresses and their IP addresses from the pcap file
        Args:

        Returns:
            dict: dictionary of MAC addresses and their IP addresses
        '''
        pkts = self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.type == 2048
            )
        ).all()
        macs = {}
        for pkt in pkts:
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
        pkts = self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.type == 2054
            )
        ).all()

        for pkt in pkts:
            arp_macs.append(pkt.eth_src)
            arp_macs.append(pkt.eth_dst)
                
        return set(arp_macs)
    
    def get_tcp_streams(self):
        '''
        Get TCP streams from the pcap file
        Args:
            pkts (list): list of packets

        Returns:
            dict: dictionary of TCP streams
        '''
        packets = self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.type == 2048,
                Packet.protocol == 6
            )
        ).all()
        streams = {}
        for row in packets:
            key = (row.ip_src, row.ip_dst) if (row.ip_src, row.ip_dst) in streams else (row.ip_dst, row.ip_src)
            if key not in streams:
                streams[key] = [row]
            else:
                streams[key].append(row)
        return streams
    
    def get_dhcp_ips(self):
        '''
        Get DHCP IP addresses from the pcap file
        Args:
            pkts (list): list of packets

        Returns:
            set: list of DHCP IP addresses
        '''
        packets = self.session.query(Packet).filter(and_(
                Packet.id_pcap == self.id_pcap,
                Packet.dhcp_yiaddr.isnot(None)
            )
        ).all()
        ips = []
        for row in packets:
            ips.append(row.dhcp_yiaddr)
        return set(ips)
    
    def get_non_dhcp_ips(self):
        '''
        Get non-DHCP IP addresses from the pcap file
        Args:
            pkts (list): list of packets

        Returns:
            set: list of non-DHCP IP addresses
        '''
        packets = self.session.query(Packet).filter(and_(
                Packet.id_pcap == self.id_pcap,
                Packet.dhcp_yiaddr == None
            )
        ).all()
        ips = []
        for row in packets:
            ips.append(row.ip_src)
            ips.append(row.ip_dst)
        return set(ips)
    
    def get_communication_channels(self, pkts, onlyTCP = True):
        '''
        Get communication channels from the pcap file
        Args:
            pkts (list): list of packets

        Returns:
            dict: dictionary of communication channels
        '''
        streams = {}
        for row in pkts:
            if row.type == 2048:
                if onlyTCP and row.protocol != 6:
                    continue
                key = (row.ip_src, row.ip_dst)
                if key not in streams:
                    streams[key] = [row]
                else:
                    streams[key].append(row)
        return streams
    
    def get_communication_channels_triplets(self, pkts):
        '''
        Get communication channels triplets (src, dst, port) from the pcap file
        Args:
            pkts (list): list of packets

        Returns:
            dict: dictionary of communication channels
        '''
        streams = {}
        for row in pkts:
            if row.type == 2048:
                key = (row.ip_src, row.ip_dst, row.port_dst)
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
            dict: dictionary of protocols
        '''
        with open('static/TCPS.json') as f:
            TCPS = set(json.load(f))
        with open('static/UDPS.json') as f:
            UDPS = set(json.load(f))

        return {6: TCPS, 17: UDPS}
    
    def get_icmp_ips(self):
        '''
        Get all IP addresses from ICMP destination unreachable packets
        Args:

        Returns:
            set: set of IP addresses
        '''
        ips = []
        packets = self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.icmp_type == 3
            )
        ).all()

        for packet in packets:
            ips.append(packet.ip_dst)

        return set(ips)
    
    def get_non_icmp_ips(self):
        '''
        Get non ICMP IP addresses from the pcap file
        Args:

        Returns:
            set: set of IP addresses
        '''
        ips = []
        packets = self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.icmp_type == None
            )
        ).all()

        for packet in packets:
            ips.append(packet.ip_src)
            ips.append(packet.ip_dst)

        return set(ips)

    def get_streams_for_ip_source(self):
        '''
        Get streams for IP source from the pcap file
        Args:

        Returns:
            dict: dictionary of streams for IP source
        '''
        packets = self.session.query(Packet).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.type == 2048
            )
        ).all()
        streams = {}
        for packet in packets:
            key = packet.ip_src
            if key not in streams:
                streams[key] = [packet]
            else:
                streams[key].append(packet)
        return streams

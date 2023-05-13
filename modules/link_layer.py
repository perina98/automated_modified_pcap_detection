##################################################
## This module checks link layer related information for any inconsistencies
##################################################
## File: link_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from database import Packet
import modules.functions as functions

class LinkLayer():
    '''
    Class for checking link layer for any inconsistencies
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
        self.functions =  functions.Functions(id_pcap, session)
        self.packets = session.query(
            Packet.type,
            Packet.eth_src,
            Packet.eth_dst,
            Packet.arp_op,
            Packet.arp_ip_src,
            Packet.arp_ip_dst
            ).filter(Packet.id_pcap == id_pcap).all()
        
    def __enter__(self):
        '''
        Enter method for 'with' block
        Args:

        Returns:
            self: object itself
        '''
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        '''
        Exit method for 'with' block
        Args:
            exc_type (mixed): exception type
            exc_value (mixed): exception value
            traceback (mixed): traceback

        Returns:
            None
        '''
        del self.functions
        del self.packets
        return

    def get_inconsistent_mac_maps(self):
        '''
        Get number of inconsistent MAC address maps
        If there is more than one IP address for one MAC address, it is considered suspicious
        Args:

        Returns:
            int: number of packets with inconsistent MAC address maps
            int: number of all IP addresses
        '''
        macs = self.functions.get_macs()
        failed = 0
        for ip in macs:
            if len(set(macs[ip])) > 1:
                failed += 1

        return failed, len(macs)
    
    def get_missing_arp_traffic(self):
        '''
        Get number of missing ARP addresses
        If the communication occurs, ARP traffic for the MAC address should be present
        Args:

        Returns:
            int: number of packets with missing ARP MAC addresses
            int: number of all macs in IP traffic
        '''
        arp_macs = []
        ip_macs = []

        for packet in self.packets:
            if packet.type == 2054:
                # ARP packet type, save MAC addresses
                arp_macs.append(packet.eth_src)
                arp_macs.append(packet.eth_dst)
            if packet.type == 2048:
                ip_macs.append(packet.eth_src)
                ip_macs.append(packet.eth_dst)
                
        failed_macs = 0
        arp_set = set(arp_macs)
        ip_set = set(ip_macs)
        for mac in ip_set:
            if mac not in arp_set:
                failed_macs += 1
        
        return failed_macs, len(ip_set)
    
    def get_lost_traffic_by_arp(self):
        '''
        Get number of MAC addresses that are not used in IP traffic but are present in ARP traffic
        Args:

        Returns:
            int: number of packets with lost ARP traffic
            int: number of all macs in ARP traffic
        '''
        arp_macs = []
        ip_macs = []

        for packet in self.packets:
            if packet.type == 2054:
                arp_macs.append(packet.eth_src)
                arp_macs.append(packet.eth_dst)
            if packet.type == 2048:
                ip_macs.append(packet.eth_src)
                ip_macs.append(packet.eth_dst)
                
        failed_macs = 0
        arp_set = set(arp_macs)
        ip_macs_set = set(ip_macs)
        for mac in arp_set:
            if mac not in ip_macs_set:
                failed_macs += 1

        return failed_macs, len(arp_set)
    
    def get_missing_arp_responses(self):
        '''
        Get number of missing ARP responses
        Args:

        Returns:
            int: number of packets with missing ARP responses
            int: number of all ARP requests
        '''
        arp_requests = []
        arp_responses = []

        for packet in self.packets:
            if packet.type == 2054:
                if packet.arp_op == 1:
                    arp_requests.append(packet.arp_ip_dst)
                if packet.arp_op == 2:
                    arp_responses.append(packet.arp_ip_src)
                
        failed_macs = 0
        requests_set = set(arp_requests)
        responses_set = set(arp_responses)
        for ip in requests_set:
            if ip not in responses_set:
                failed_macs += 1

        return failed_macs, len(requests_set)

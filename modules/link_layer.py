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
        self.id_pcap = id_pcap
        self.session = session
        self.functions =  functions.Functions(id_pcap, session)

    def get_inconsistent_mac_maps(self):
        '''
        Get number of inconsistent MAC address maps
        If there is more than one MAC address for one IP address, it is considered suspicious
        Args:

        Returns:
            int: number of inconsistent MAC address maps
        '''
        macs = self.functions.get_macs()
        failed = 0
        for ip in macs:
            if len(set(macs[ip])) > 1:
                failed += 1
        return failed
    
    def get_missing_arp_traffic(self):
        '''
        Get number of missing ARP IP addresses
        If the communication occurs, ARP traffic for the IP address should be present
        Args:

        Returns:
            int: number of failed ARP IP addresses
        '''
        arp_macs = []
        ip_macs = []
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        for pkt in pkts:
            if pkt.type == 2054:
                # ARP packet type, save MAC addresses
                arp_macs.append(pkt.eth_src)
                arp_macs.append(pkt.eth_dst)
            if pkt.type == 2048:
                ip_macs.append({'src': pkt.eth_src, 'dst': pkt.eth_dst})
                
        failed_macs = 0
        arp_set = set(arp_macs)
        for mac in ip_macs:
            if mac['src'] not in arp_set and mac['dst'] not in arp_set:
                failed_macs += 1
        
        return failed_macs
    
    def get_lost_traffic_by_arp(self):
        '''
        Get number of MAC addresses that are not used in IP traffic but are present in ARP traffic
        Args:

        Returns:
            int: number of failed ARP IP addresses
        '''
        arp_macs = []
        ip_macs = []
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        for pkt in pkts:
            if pkt.type == 2054:
                arp_macs.append(pkt.eth_src)
                arp_macs.append(pkt.eth_dst)
            if pkt.type == 2048:
                ip_macs.append(pkt.eth_src)
                ip_macs.append(pkt.eth_dst)
                
        failed_macs = 0
        arp_set = set(arp_macs)
        ip_macs_set = set(ip_macs)
        for mac in arp_set:
            if mac not in ip_macs_set:
                failed_macs += 1

        return failed_macs
    
    def get_missing_arp_responses(self):
        '''
        Get number of missing ARP responses
        Args:

        Returns:
            int: number of missing ARP responses
        '''
        arp_requests = []
        arp_responses = []
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        for pkt in pkts:
            if pkt.type == 2054:
                if pkt.arp_op == 1:
                    arp_requests.append(pkt.arp_ip_dst)
                if pkt.arp_op == 2:
                    arp_responses.append(pkt.arp_ip_src)
                
        failed_macs = 0
        for ip in arp_requests:
            if ip not in arp_responses:
                failed_macs += 1

        return failed_macs

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

    def get_failed_mac_maps(self):
        '''
        Get number of failed MAC address maps
        If there is more than one MAC address for one IP address, it is considered suspicious
        Args:

        Returns:
            int: number of failed MAC address maps
        '''
        macs = self.functions.get_macs()
        failed = 0
        for ip in macs:
            if len(set(macs[ip])) > 1:
                failed += 1
        return failed
    
    def get_failed_arp_ips(self):
        '''
        Get number of failed ARP IP addresses
        At least one of the communicating MAC addresses must be in ARP packets
        If not, it is considered suspicious
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
                ip_macs.append({'src': pkt.eth_src, 'dst': pkt.eth_dst})
                
        failed_macs = 0
        arp_set = set(arp_macs)
        for mac in ip_macs:
            if mac['src'] not in arp_set and mac['dst'] not in arp_set:
                failed_macs += 1
        
        return failed_macs

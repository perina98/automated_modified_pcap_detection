##################################################
## This module checks internet layer related information for any inconsistencies
##################################################
## File: internet_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from database import Packet
import modules.functions as functions

class InternetLayer():
    '''
    Class for checking internet layer for any inconsistencies
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

    def get_inconsistent_ttls(self):
        '''
        POROVNAT IBA SYN PAKETY, IBA ZACIATOK SPOJENIA, mozno aj pre window
        Get number of inconsistent TTL values
        If the TTL value is different in the same communication, it is considered suspicious
        Args:

        Returns:
            int: number of inconsistent TTL values
        '''
        packets = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()
        channels = self.functions.get_communication_channels(packets)

        failed = 0
        for stream in channels:
            channels[stream].sort(key=lambda x: x.packet_timestamp)
            stream_ttls = {}
            for i in range(len(channels[stream])):
                if channels[stream][i].ttl not in stream_ttls:
                    stream_ttls[channels[stream][i].ttl] = 1
                else:
                    stream_ttls[channels[stream][i].ttl] += 1
            
            if len(stream_ttls) > 2:
                failed += len(channels[stream])
            
        return failed
    
    def get_inconsistent_fragmentation(self):
        '''
        Get number of packets with inconsistent fragmentation

        Args:
        
        Returns:
            int: number of packets with inconsistent fragmentation
        '''

        packets = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap and Packet.ip_identification != 0 and Packet.ip_identification is not None).all()

        # save packets to dictionary by ip_identification
        ip_identifications = {}
        for packet in packets:
            if packet.ip_identification not in ip_identifications:
                ip_identifications[packet.ip_identification] = []
            
            ip_identifications[packet.ip_identification].append(packet)

        failed = 0

        for id in ip_identifications:
            if len(ip_identifications[id]) == 1:
                if ip_identifications[id][0].ip_flag == 1 or ip_identifications[id][0].ip_fragment_offset != 0:
                    failed += 1
            if len(ip_identifications[id]) > 1:
                for i in range(len(ip_identifications[id])):
                    if (i != len(ip_identifications[id]) - 1 and ip_identifications[id][i].ip_flag != 1) or (i == 0 and ip_identifications[id][i].ip_fragment_offset != 0):
                        failed += 1
                        break

        return failed

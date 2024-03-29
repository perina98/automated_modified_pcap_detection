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
from sqlalchemy import and_

class InternetLayer():
    '''
    Class for checking internet layer for any inconsistencies
    '''
    def __init__(self, config, id_pcap, session):
        '''
        Constructor
        Args:
            config (Config): configuration object
            id_pcap (int): id of the pcap file in the database
            session (mixed): database session

        Returns:
            None
        '''
        self.id_pcap = id_pcap
        self.session = session
        self.config = config
        self.functions =  functions.Functions(id_pcap, session)

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
        return

    def get_inconsistent_ttls(self):
        '''
        Get number of inconsistent TTL values
        If the TTL value is different in the same communication, it is considered suspicious
        Args:

        Returns:
            int: number of inconsistent TTL values
            int: number of communication channels
        '''
        packets = self.session.query(
            Packet.tcp_flags,
            Packet.ttl, 
            Packet.protocol, 
            Packet.ip_src, 
            Packet.ip_dst
            ).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.type == 2048
            )
            ).all()
        channels = self.functions.get_communication_channels(packets)

        failed = 0
        for stream in channels:
            stream_ttls = {}
            for i in range(len(channels[stream])):
                if channels[stream][i].tcp_flags != 'S':
                    continue
                if channels[stream][i].ttl not in stream_ttls:
                    stream_ttls[channels[stream][i].ttl] = 1
                else:
                    stream_ttls[channels[stream][i].ttl] += 1
            
            # allowed number of different TTL values is set to 2, can be discussed and changed
            # generally, ttls should be the same for the same communication
            if len(stream_ttls) > 2:
                failed += 1

        return failed, len(channels)
    
    def get_inconsistent_fragmentation(self):
        '''
        Get number of packets with inconsistent fragmentation
        Also checks for ip_identification = 0, which indicates issues with the packet
        Args:
        
        Returns:
            int: number of packets with inconsistent fragmentation
            int: number of ip_identifications by communication stream
        '''
        packets = self.session.query(
            Packet.ip_src,
            Packet.ip_dst,
            Packet.ip_identification,
            Packet.ip_flag,
            Packet.ip_fragment_offset
            ).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.ip_identification != 0,
                Packet.type == 2048,
                Packet.ip_identification.isnot(None)
            )
        ).all()
        ip_identifications_by_stream = {}
        channels = self.functions.get_communication_channels(packets, False)
        for stream in channels:
            for packet in channels[stream]:
                if (packet.ip_src, packet.ip_dst, packet.ip_identification) not in ip_identifications_by_stream:
                    ip_identifications_by_stream[(packet.ip_src, packet.ip_dst, packet.ip_identification)] = []
                
                ip_identifications_by_stream[(packet.ip_src, packet.ip_dst, packet.ip_identification)].append(packet)

        failed = 0
       
        for stream in ip_identifications_by_stream:
            # if there is only one packet in the stream, there should be no fragmentation
            if len(ip_identifications_by_stream[stream]) == 1:
                if ip_identifications_by_stream[stream][0].ip_flag == 0 and ip_identifications_by_stream[stream][0].ip_fragment_offset != 0:
                    failed += 1
                if ip_identifications_by_stream[stream][0].ip_flag == 1 or ip_identifications_by_stream[stream][0].ip_fragment_offset != 0:
                    failed += 1
            # if there are more packets in the stream, fragmentation is possible, but not in all cases
            if len(ip_identifications_by_stream[stream]) > 1:
                for i in range(len(ip_identifications_by_stream[stream])):
                    if ip_identifications_by_stream[stream][i].ip_flag == 0:
                        if i == len(ip_identifications_by_stream[stream]) - 1 and ip_identifications_by_stream[stream][i].ip_fragment_offset == 0:
                            failed += 1
                            break
                        if i != len(ip_identifications_by_stream[stream]) - 1:
                            failed += 1
                            break
                    if (i != len(ip_identifications_by_stream[stream]) - 1 and ip_identifications_by_stream[stream][i].ip_flag != 1) or (i == 0 and ip_identifications_by_stream[stream][i].ip_fragment_offset != 0):
                        failed += 1
                        break
        return failed, len(ip_identifications_by_stream)

    def get_sudden_ip_source_traffic_drop(self):
        '''
        Get number of packets with sudden drop for IP source traffic
        Args:

        Returns:
            int: number of packets with sudden drop for IP source traffic
            int: number of communication channels for IP source traffic
        '''
        streams_for_ip_source = self.functions.get_streams_for_ip_source()
        failed = 0
        gap = 0
        for stream in streams_for_ip_source:
            for i in range(len(streams_for_ip_source[stream]) - 1):
                gap = streams_for_ip_source[stream][i+1].packet_timestamp - streams_for_ip_source[stream][i].packet_timestamp

                if gap > self.config['app']['allowed_communication_silence']:
                    failed += 1
                    break
        return failed, len(streams_for_ip_source)
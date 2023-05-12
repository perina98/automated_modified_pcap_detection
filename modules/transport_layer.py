##################################################
## This module checks transport layer for any inconsistencies
##################################################
## File: transport_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import json
from scapy.all import *
from database import Packet
import modules.functions as functions
from sqlalchemy import and_

class TransportLayer():
    '''
    Class for checking transport layer for any inconsistencies
    '''
    def __init__(self, config, id_pcap, session):
        '''
        Constructor
        Args:
            id_pcap (int): id of the pcap file in the database
            session (mixed): database session

        Returns:
            None
        '''
        funct =  functions.Functions(id_pcap, session)
        self.config = config
        self.functions = funct
        self.streams = funct.get_tcp_streams()
        self.channels = funct.get_communication_channels(session.query(
            Packet.ip_src,
            Packet.ip_dst,
            Packet.protocol,
            Packet.tcp_flags,
            Packet.mss,
            Packet.window
            ).filter(
            and_(
                Packet.id_pcap == id_pcap,
                Packet.type == 2048
            )
        ).all())
    
    def get_inconsistent_interpacket_gaps(self):
        '''
        Check if the response time is more than x times different than the first response time in TCP handshake
        Args:

        Returns:
            int: Number of streams with inconsistent interpacket gaps
            int: Number of tcp streams
        '''
        failed = 0

        for stream in self.streams:
            stream_ref_time = 0
            for i in range(len(self.streams[stream]) - 1):
                if self.streams[stream][i].tcp_flags == 'S':
                    syn = self.streams[stream][i]
                    synack = self.functions.find_synack(i, syn.seq+1, self.streams[stream])
                    if stream_ref_time == 0:
                        if synack != None:
                            stream_ref_time = abs(synack.packet_timestamp - syn.packet_timestamp)
                            continue
                        if i == len(self.streams[stream]) - 2:
                            continue # incomplete tcp stream

                    if synack == None:
                        continue

                    current_diff = abs(synack.packet_timestamp - syn.packet_timestamp)

                    allowed_latency_inconsistency = self.config['app']['allowed_latency_inconsistency'] * stream_ref_time
                    if current_diff > allowed_latency_inconsistency:
                        failed += 1
                        break

        return failed, len(self.streams)
    
    def get_incomplete_tcp_streams(self):
        '''
        Check if the TCP stream starts with a SYN / SYN-ACK
        Args:

        Returns:
            int: Number of streams with missing SYN / SYN-ACK
            int: Number of tcp streams
        '''
        failed = 0

        for stream in self.streams:
            stream_ref_time = 0
            for i in range(len(self.streams[stream]) - 1):
                if self.streams[stream][i].tcp_flags == 'S' or self.streams[stream][i].tcp_flags == 'SEC':
                    syn = self.streams[stream][i]
                    synack = self.functions.find_synack(i, syn.seq+1, self.streams[stream])
                    if stream_ref_time == 0:
                        if synack != None:
                            stream_ref_time = abs(synack.packet_timestamp - syn.packet_timestamp)
                            break
                        else:
                            failed += 1
                            break
                if stream_ref_time == 0 and i == len(self.streams[stream]) - 2:
                    failed += 1
                    break
        
        return failed, len(self.streams)

    def get_inconsistent_mss(self):
        '''
        Check if the MSS value is different in the same communication
        Args:

        Returns:
            int: Number of packets with inconsistent MSS
            int: Number of communication channels
        '''
        failed = 0

        for stream in self.channels:
            stream_mss = {}
            for i in range(len(self.channels[stream])):
                if self.channels[stream][i].tcp_flags == 'S':
                    if self.channels[stream][i].mss not in stream_mss:
                        stream_mss[self.channels[stream][i].mss] = 0
                    stream_mss[self.channels[stream][i].mss] += 1
            
            if len(stream_mss) > 1:
                failed += 1

        
        return failed, len(self.channels)
    
    def get_inconsistent_window(self):
        '''
        Check if the window size value is different in the same communication
        Args:

        Returns:
            int: Number of packets with inconsistent window size
            int: Number of communication channels
        '''
        failed = 0

        for stream in self.channels:
            stream_window = {}
            for i in range(len(self.channels[stream])):
                if self.channels[stream][i].tcp_flags == 'S':
                    if self.channels[stream][i].window not in stream_window:
                        stream_window[self.channels[stream][i].window] = 1
                    else:
                        stream_window[self.channels[stream][i].window] += 1
            if len(stream_window) > 1:
                failed += 1

        return failed, len(self.channels)
    
    def get_mismatched_ciphers(self):
        '''
        Check if the cipher in server hello is in the client hello
        Args:

        Returns:
            int: Number of packets with mismatched ciphers
            int: Number of tcp streams
        '''
        failed = 0

        for stream in self.streams:
            stream_ciphers = {'client': [], 'server': []}
            for i in range(len(self.streams[stream])):
                if self.streams[stream][i].tls_msg_type == 1 and self.streams[stream][i].tls_ciphers:
                    if len(stream_ciphers['client']) > 1:
                        # compare the ciphers, the two lists should be the same, order doesn't matter
                        try:
                            if set(stream_ciphers['client']) != set(json.loads(self.streams[stream][i].tls_ciphers)):
                                failed += 1
                                break
                        except TypeError:
                            continue
                    try:
                        stream_ciphers['client'] = list(set(stream_ciphers['client'] + json.loads(self.streams[stream][i].tls_ciphers)))
                    except TypeError:
                        continue
                elif self.streams[stream][i].tls_msg_type == 2 and self.streams[stream][i].tls_ciphers:
                    stream_ciphers['server'].append(json.loads(self.streams[stream][i].tls_ciphers))
                else:
                    continue

            p = 0
            for j in range(len(stream_ciphers['server'])):
                if stream_ciphers['server'][j] in stream_ciphers['client']:
                    p = 1
                    break
            if p == 0 and len(stream_ciphers['server']) > 0 and len(stream_ciphers['client']) > 0:
                failed += 1
                break

        return failed, len(self.streams)

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

class TransportLayer():
    '''
    Class for checking transport layer for any inconsistencies
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
    
    def get_inconsistent_interpacket_gaps(self):
        '''
        Check if the response time is more than 2x the average response time
        Args:

        Returns:
            None
        '''
        streams = self.functions.get_tcp_streams(self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all())
        failed = 0

        for stream in streams:
            streams[stream].sort(key=lambda x: x.packet_timestamp)
            stream_ref_time = 0
            for i in range(len(streams[stream]) - 1):
                if streams[stream][i].ack == 0 and streams[stream][i + 1].ack == streams[stream][i].seq + 1:
                    if stream_ref_time == 0:
                        stream_ref_time = abs(streams[stream][i + 1].packet_timestamp - streams[stream][i].packet_timestamp)
                        continue

                    current_diff = abs(streams[stream][i + 1].packet_timestamp - streams[stream][i].packet_timestamp)
                    if current_diff > stream_ref_time * 2:
                        failed += 1

        return failed
    
    def get_inconsistent_mss(self):
        '''
        Check if the MSS value is different in the same communication
        Args:

        Returns:
            None
        '''
        channels = self.functions.get_communication_channels(self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all())
        failed = 0

        for stream in channels:
            stream_mss = {}
            for i in range(len(channels[stream])):
                if channels[stream][i].mss not in stream_mss:
                    stream_mss[channels[stream][i].mss] = 1
                else:
                    stream_mss[channels[stream][i].mss] += 1
            
            if len(stream_mss) > 2:
                failed += len(channels[stream])
        
        return failed
    
    def get_inconsistent_window(self):
        '''
        Check if the window size value is different in the same communication
        Args:

        Returns:
            None
        '''
        channels = self.functions.get_communication_channels(self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all())
        failed = 0

        for stream in channels:
            windows = {}
            for i in range(len(channels[stream])):
                if channels[stream][i].window not in windows:
                    windows[channels[stream][i].window] = 1
                else:
                    windows[channels[stream][i].window] += 1
            
            if len(windows) > 2:
                failed += len(channels[stream])
        
        return failed
    
    def get_mismatched_ciphers(self):
        '''
        Check if the cipher in server hello is in the client hello
        Args:

        Returns:
            None
        '''
        streams = self.functions.get_tcp_streams(self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all())
        failed = 0

        for stream in streams:
            stream_ciphers = {'client': [], 'server': []}
            for i in range(len(streams[stream])):
                if streams[stream][i].tls_msg_type == 1 and streams[stream][i].tls_ciphers:
                    if len(stream_ciphers['client']) > 1:
                        # compare the ciphers, the two lists should be the same, order doesn't matter
                        if set(stream_ciphers['client']) != set(json.loads(streams[stream][i].tls_ciphers)):
                            print(set(stream_ciphers['client']), set(json.loads(streams[stream][i].tls_ciphers)))
                            failed += 1
                            break
                    stream_ciphers['client'] = list(set(stream_ciphers['client'] + json.loads(streams[stream][i].tls_ciphers)))
                elif streams[stream][i].tls_msg_type == 2 and streams[stream][i].tls_ciphers:
                    stream_ciphers['server'].append(json.loads(streams[stream][i].tls_ciphers))
                else:
                    continue

            p = 0
            for j in range(len(stream_ciphers['server'])):
                if stream_ciphers['server'][j] in stream_ciphers['client']:
                    p = 1
                    break
            if p == 0 and len(stream_ciphers['server']) > 0 and len(stream_ciphers['client']) > 0:
                failed += len(streams[stream])
                break

        return failed

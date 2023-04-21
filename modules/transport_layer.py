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
            int: Number of packets with inconsistent interpacket gaps
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
            int: Number of packets with inconsistent MSS
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
        !!!!! TOTO TREBA OVERIT !!!!!, mozno iba pre SYN pakety
        Check if the window size value is different in the same communication
        Args:

        Returns:
            int: Number of packets with inconsistent window size
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
            int: Number of packets with mismatched ciphers
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

    def get_incomplete_tcp_streams(self):
        '''
        WIP
        Check TCP stream seq numbers, WIP
        Args:

        Returns:
            int: Number of packets with incomplete TCP streams
        '''

        streams = self.functions.get_tcp_streams(self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all())
        failed = 0

        for stream in streams:
            if streams[stream][0].tcp_flags != 'S':
                failed += len(streams[stream])
                continue
            if not 'R' in streams[stream][-1].tcp_flags and not 'F' in streams[stream][-1].tcp_flags:
                failed += len(streams[stream])
                continue
            
            initiator_port = streams[stream][0].port_src
            target_port = streams[stream][0].port_dst

            ports = set([initiator_port, target_port])  # set of communicating ports
            seq_nums = {p: 0 for p in ports}  # current expected seq numbers

            for i in range(len(streams[stream])):
                port = streams[stream][i].port_src
                seq = streams[stream][i].seq
                tcp_segment_length = streams[stream][i].tcp_segment_len
                tcp_flags = streams[stream][i].tcp_flags

                if tcp_flags == 'S':
                    seq_nums[initiator_port] = seq + 1
                    continue

                if tcp_flags == 'SA':
                    seq_nums[target_port] = seq + 1
                    continue

                if port == initiator_port:
                    if seq != seq_nums[initiator_port]:
                        #print ('seq mismatch', seq, seq_nums[initiator_port])
                        failed += 1
                    else:
                        pass
                        #print('checked seq ', seq, seq_nums[initiator_port])

                elif port == target_port and i+1 < len(streams[stream]):
                    if seq != seq_nums[target_port] and streams[stream][i+1].port_src == initiator_port:
                        #print('seq target mismatch', seq, seq_nums[target_port])
                        failed += 1
                    else:
                        pass
                        #print('checked seq ', seq, seq_nums[target_port])

                seq_nums[port] = seq + tcp_segment_length

        return failed

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
    
    def get_failed_response_times(self):
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

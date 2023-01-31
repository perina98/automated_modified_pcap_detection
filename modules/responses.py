##################################################
## This modules checks the response times between packets in one stream
##################################################
## File: macs.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from modules.db import Packet

class Responses():
    def get_tcp_streams(self, pkts):
        streams = {}
        for row in pkts:
            if row.type == 2048 and row.protocol == 6:
                if streams.get((row.ip_src, row.ip_dst, row.port_src, row.port_dst, row.length)) == None:
                    streams[(row.ip_src, row.ip_dst, row.port_src, row.port_dst, row.length)] = [row]
                else:
                    streams[(row.ip_src, row.ip_dst, row.port_src, row.port_dst, row.length)].append(row)
        return streams
        

    def get_failed_response_times(self, id_pcap, session):
        streams = self.get_tcp_streams(session.query(Packet).filter(Packet.id_pcap == id_pcap).all())
        
        last_diff = 0
        failed = 0
        
        for stream in streams:
            streams[stream].sort(key=lambda x: x.packet_timestamp)
            for i in range(len(streams[stream]) - 1):
                current_diff = abs(streams[stream][i + 1].packet_timestamp - streams[stream][i].packet_timestamp)
                if last_diff != 0 and current_diff > last_diff * 1000000:
                    failed += 1
                last_diff = current_diff

        return failed
        
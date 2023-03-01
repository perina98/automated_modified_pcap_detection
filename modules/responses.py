##################################################
## This modules checks the response times between packets in one stream
##################################################
## File: responses.py
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
                key = (row.ip_src, row.ip_dst) if (row.ip_src, row.ip_dst) in streams else (row.ip_dst, row.ip_src)
                if key not in streams:
                    streams[key] = [row]
                else:
                    streams[key].append(row)
        return streams
        

    def get_failed_response_times(self, id_pcap, session):
        streams = self.get_tcp_streams(session.query(Packet).filter(Packet.id_pcap == id_pcap).all())
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
                        print (stream_ref_time, current_diff, streams[stream][i].packet_timestamp, streams[stream][i + 1].packet_timestamp)
                        failed += 1

        return failed
        
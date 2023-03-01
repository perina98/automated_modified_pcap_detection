##################################################
## This modules checks application layer for any inconsistencies
##################################################
## File: app_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import json
from scapy.all import *
from modules.db import Packet
from modules import arp

class AppLayer():
    def get_dns_packets(self, id_pcap, session):
        return session.query(Packet).filter(Packet.id_pcap == id_pcap, Packet.protocol == 17).all()

    def get_dns_pairs(self, id_pcap, session):
        pkts = self.get_dns_packets(id_pcap, session)
        pairs = {}

        for pkt in pkts:
            if pkt.dns:
                dns = json.loads(pkt.dns)
                if dns['id'] not in pairs:
                    pairs[dns['id']] = {}
                    pairs[dns['id']]['time'] = pkt.packet_timestamp
                if dns['an']:
                    pairs[dns['id']]['answer'] = dns['an']
                else:
                    pairs[dns['id']]['query'] = dns['qd']
                    pairs[dns['id']]['type'] = dns['qd']['qtype'] if dns['qd'] is not None else 0

        # filter only pairs with query and answer
        return {k: v for k, v in pairs.items() if 'query' in v and 'answer' in v}

    # check if there is any DNS packet with different query and response
    def get_failed_dns_query_answer(self, id_pcap, session):
        pairs = self.get_dns_pairs(id_pcap, session)
        failed = 0
        for pair in pairs:
            for an in pairs[pair]['answer']:
                if an['rrname'] != pairs[pair]['query']['qname']:
                    failed += 1
        return failed

    # check A and AAAA records and check if the IP address appreared before the pkt time
    def get_failed_dns_answer_time(self, id_pcap, session):
        pairs = self.get_dns_pairs(id_pcap, session)

        pairs = {k: v for k, v in pairs.items() if v['type'] == 1 or v['type'] == 28}

        ip_addresses = {}
        for pair in pairs:
            for an in pairs[pair]['answer']:
                if an['rdata'] not in ip_addresses:
                    ip_addresses[an['rdata']] = []
                ip_addresses[an['rdata']].append(pairs[pair]['time'])
        
        pkts = session.query(Packet).filter(Packet.id_pcap == id_pcap).all()

        failed = 0

        for pkt in pkts:
            if pkt.ip_src in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_src]):
                    failed += 1
            if pkt.ip_dst in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_dst]):
                    failed += 1

        return failed        


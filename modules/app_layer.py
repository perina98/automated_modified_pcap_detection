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
import dns.resolver
from scapy.all import *
from modules.db import Packet

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
                if dns['an']:
                    pairs[dns['id']]['answer'] = dns['an']
                else:
                    pairs[dns['id']]['query'] = dns['qd']

        # filter only pairs with query and answer
        return {k: v for k, v in pairs.items() if 'query' in v and 'answer' in v}

    # check if there is any DNS packet with different query and response
    def get_failed_dns(self, id_pcap, session):
        pairs = self.get_dns_pairs(id_pcap, session)
        failed = 0
        for pair in pairs:
            for an in pairs[pair]['answer']:
                if an['rrname'] != pairs[pair]['query']['qname']:
                    failed += 1
                
                if an['type'] == 5:
                    try:
                        answer = dns.resolver.query(pairs[pair]['query']['qname'], 'CNAME')
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        answer = None

                    if answer:
                        success = False
                        for a in answer:
                            if an['rdata'] == a.target.to_text() and an['rdata'] != '':
                                success = True

                        if not success:
                            failed += 1

                if an['type'] == 1:
                    try:
                        answer = dns.resolver.query(pairs[pair]['query']['qname'], 'A')
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        answer = None

                    if answer:
                        success = False
                        for a in answer:
                            if an['rdata'] != a.address and an['rdata'] != '':
                                success = True
                        
                        if not success:
                            failed += 1
                

        return failed

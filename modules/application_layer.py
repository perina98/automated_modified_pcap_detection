##################################################
## This module checks application layer for any inconsistencies
##################################################
## File: application_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from database import Packet
import modules.functions as functions

class ApplicationLayer():
    '''
    Class for checking application layer for any inconsistencies
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
        self.dns_pairs = self.functions.get_dns_pairs()

    def get_translation_of_unvisited_domains(self):
        '''
        Check if the trace contains a translation of the domain that has not been visited after the translation
        Args:

        Returns:
            int: number of packets with translation of unvisited domains
        '''

        packets = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        all_ips = [pkt.ip_dst for pkt in packets]

        failed_count = 0

        for pair in self.dns_pairs.values():
            valid_answer = False
            has_ip_answer = False
            for answer in pair['answers']:
                if answer['atype'] in (1, 28):
                    has_ip_answer = True
                    if answer['answer']['rdata'] in all_ips:
                        valid_answer = True
            if has_ip_answer and not valid_answer:
                failed_count += 1

        return failed_count
    
    def get_incomplete_ftp(self):
        '''
        Check if the trace contains a FTP and FTP-DATA protocol. If one is present the other should be present as well.
        Check all IP address pairs
        Args:

        Returns:
            int: number of IP pairs with incomplete FTP
        '''

        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap and 
                                                (Packet.port_dst == 21 or Packet.port_src == 21 or Packet.port_dst == 20 or Packet.port_src == 20) 
                                                ).all()

        failed = 0
        pairs = {}
        for pkt in pkts:
            # check if the packet is FTP
            if pkt.port_src == 21 or pkt.port_dst == 21:
                # check if the IP address pair is in the dictionary
                key = (pkt.ip_src, pkt.ip_dst) if (pkt.ip_src, pkt.ip_dst) in pairs else (pkt.ip_dst, pkt.ip_src)
                if key not in pairs:
                    pairs[key] = {'ftp': False, 'ftp-data': False}
                pairs[key]['ftp'] = True
            
            # check if the packet is FTP-DATA
            if pkt.port_src == 20 or pkt.port_dst == 20:
                key = (pkt.ip_src, pkt.ip_dst) if (pkt.ip_src, pkt.ip_dst) in pairs else (pkt.ip_dst, pkt.ip_src)
                if key not in pairs:
                    # FTP-DATA should not come before FTP
                    failed += 1
                else:
                    pairs[key]['ftp-data'] = True

        # check if the FTP and FTP-DATA are present in the same IP address pair
        for pair in pairs:
            if pairs[pair]['ftp'] != pairs[pair]['ftp-data']:
                failed += 1

        return failed


    def get_mismatched_dns_query_answer(self):
        '''
        Check if there is any DNS packet with different query in query and response packets
        Args:

        Returns:
            int: number of mismatched DNS query and answer pairs
        '''
        failed = 0

        for pair in self.dns_pairs:
            if self.dns_pairs[pair]['query']['qname'] != self.dns_pairs[pair]['answer_query']:
                failed += 1

        return failed


        
    
    def get_mismatched_dns_answer_stack(self):
        '''
        Check if there is any DNS packet with mismatched answer stack
        If there is a CNAME record, the next record should correspond to the CNAME record before it
        Args:

        Returns:
            int: number of mismatched DNS answer stacks
        '''
        failed = 0

        for pair in self.dns_pairs:
            f = False
            cname_context = []
            for idx,an in enumerate(self.dns_pairs[pair]['answers']):
                if an['atype'] == 5:
                    cname_context.append(an['answer']['rdata'])
                    if idx == 0:
                        continue
                    if cname_context[-2] != an['answer']['rrname']:
                        f = True
                        print (cname_context[-2],an['answer']['rrname'])
            failed += 1 if f else 0

        return failed

    def get_missing_translation_of_visited_domain(self):
        '''
        Check A and AAAA records and check if the IP address appreared before the pkt time
        This would indicate that the IP address was spoofed
        Args:

        Returns:
            int: number of failed DNS query and answer pairs
        '''
        # filter only A and AAAA records
        pairs = {k: v for k, v in self.dns_pairs.items() if v['qtype'] == 1 or v['qtype'] == 28}

        ip_addresses = {}
        for pair in pairs:
            for an in pairs[pair]['answers']:
                # check if an['atype'] is A or AAAA
                if an['atype'] != 1 and an['atype'] != 28:
                    continue
                if an['answer']['rdata'] not in ip_addresses:
                    ip_addresses[an['answer']['rdata']] = []
                ip_addresses[an['answer']['rdata']].append(an['atime'])
                
        # get all packets from the pcap file
        pkts = self.session.query(Packet).filter(Packet.id_pcap == self.id_pcap).all()

        failed = 0

        for pkt in pkts:
            if self.functions.is_private_ip(pkt.ip_src) or self.functions.is_private_ip(pkt.ip_dst):
                continue
            if pkt.ip_src in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_src]):
                    failed += 1
            if pkt.ip_dst in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_dst]):
                    failed += 1

        return failed        


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
from sqlalchemy import and_, or_

class ApplicationLayer():
    '''
    Class for checking application layer for any inconsistencies
    '''
    def __init__(self, config, id_pcap, session):
        '''
        Constructor
        Args:
            config (dict): configuration dictionary
            id_pcap (int): id of the pcap file in the database
            session (mixed): database session

        Returns:
            None
        '''
        self.id_pcap = id_pcap
        self.session = session
        self.functions =  functions.Functions(id_pcap, session, config)
        self.dns_pairs = self.functions.get_dns_pairs()

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
        del self.dns_pairs
        return

    def get_translation_of_unvisited_domains(self):
        '''
        Check if the trace contains a translation of the domain that has not been visited after the translation
        Args:

        Returns:
            int: number of unvisited domains
            int: number of all dns pairs
        '''
        packets = self.session.query(Packet.ip_dst).filter(Packet.id_pcap == self.id_pcap).all()

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

        return failed_count, len(self.dns_pairs)
    
    def get_incomplete_ftp(self):
        '''
        Check if the trace contains a FTP and FTP-DATA protocol. If one is present the other should be present as well.
        Check all IP address pairs
        Args:

        Returns:
            int: number of IP pairs with incomplete FTP
            int: number of FTP pairs
        '''
        streams = self.functions.get_tcp_streams()

        failed = 0
        ftp_streams = {}
        is_ftp = False

        # for each stream check that 3 way handshake is present
        for stream in streams:
            if len(streams[stream]) < 3:
                continue

            threeway = {'S': False, 'SA': False, 'A': False}
            connected = False
            for pkt in streams[stream]:
                # check if the packet is 3 way handshake
                if connected == False:
                    if pkt.tcp_flags == 'S' or pkt.tcp_flags == 'SA' or pkt.tcp_flags == 'A':
                        threeway[pkt.tcp_flags] = True
                        if threeway['S'] and threeway['SA'] and threeway['A']:
                            connected = True
                        continue
                if connected and pkt.is_ftp == 1:
                    is_ftp = True
                    break
            
            if is_ftp:
                ftp_streams[stream] = streams[stream]
                is_ftp = False

        pairs = {}
        for stream in ftp_streams:
            for pkt in ftp_streams[stream]:
                if pkt.port_src == 21 or pkt.port_dst == 21:
                    # check if the IP address pair is in the dictionary
                    if stream not in pairs:
                        pairs[stream] = {'ftp': False, 'ftp-data': False}
                    pairs[stream]['ftp'] = True
                
                # check if the packet is FTP-DATA
                if pkt.port_src == 20 or pkt.port_dst == 20:
                    if stream not in pairs:
                        # FTP-DATA should not come before FTP
                        failed += 1
                    else:
                        pairs[stream]['ftp-data'] = True

        # check if the FTP and FTP-DATA are present in the same IP address pair
        for pair in pairs:
            if pairs[pair]['ftp'] != pairs[pair]['ftp-data']:
                failed += 1

        return failed, len(pairs)

    def get_mismatched_dns_query_answer(self):
        '''
        Check if there is any DNS packet with different query in query and response packets
        Args:

        Returns:
            int: number of mismatched DNS query and answer pairs
            int: number of all dns pairs
        '''
        failed = 0

        for pair in self.dns_pairs:
            if self.dns_pairs[pair]['query']['qname'] != self.dns_pairs[pair]['answer_query']:
                failed += 1

        return failed, len(self.dns_pairs)

    def get_mismatched_dns_answer_stack(self):
        '''
        Check if there is any DNS packet with mismatched answer stack
        If there is a CNAME record, the next record should correspond to the CNAME record before it
        Args:

        Returns:
            int: number of mismatched DNS answer stacks
            int: number of all dns pairs
        '''
        failed = 0

        for pair in self.dns_pairs:
            f = False
            cname_context = []
            for idx,an in enumerate(self.dns_pairs[pair]['answers']):
                if an['atype'] == 5: # CNAME
                    cname_context.append(an['answer']['rdata'])
                    if idx == 0:
                        continue
                    # rdata in the previous answer should be the same as the rrname in the current answer, if it is CNAME
                    if cname_context[-2] != an['answer']['rrname']:
                        f = True
                        break
            failed += 1 if f else 0

        return failed, len(self.dns_pairs)

    def get_missing_translation_of_visited_domain(self):
        '''
        Check A and AAAA records and check if the IP address appreared before the pkt time
        This would indicate that the IP address was spoofed
        Args:

        Returns:
            int: number of failed DNS query and answer pairs
            int: number of all packets
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
        pkts = self.session.query(
            Packet.ip_src,
            Packet.ip_dst,
            Packet.packet_timestamp
            ).filter(Packet.id_pcap == self.id_pcap).all()

        failed = 0

        for pkt in pkts:
            if not self.functions.is_private_ip(pkt.ip_src) and pkt.ip_src in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_src]):
                    failed += 1
                    continue
            if not self.functions.is_private_ip(pkt.ip_dst) and pkt.ip_dst in ip_addresses:
                if pkt.packet_timestamp < min(ip_addresses[pkt.ip_dst]):
                    failed += 1
                    continue

            if (not self.functions.is_private_ip(pkt.ip_src) and pkt.ip_src not in ip_addresses) or \
                (not self.functions.is_private_ip(pkt.ip_dst) and pkt.ip_dst not in ip_addresses):
                failed += 1

        return failed, len(pkts)        
    
    def get_missing_dhcp_ips(self):
        '''
        If IP address is in DHCP, it should also appear in other connections in packet capture
        Args:

        Returns:
            int: Number of packets with missing DHCP IPs
            int: Number of all DHCP IPs
        '''
        # get all IPs from DHCP packets
        dhcp_ips = self.functions.get_dhcp_ips()

        # get all IPs from other packets
        other_ips = self.functions.get_non_dhcp_ips()

        # check if all DHCP IPs are in other IPs
        failed = 0
        for ip in dhcp_ips:
            if ip not in other_ips and ip != '0.0.0.0':
                failed += 1

        return failed, len(dhcp_ips)
    
    def get_missing_icmp_ips(self):
        '''
        If IP address is in ICMP, it should also appear in other connections in packet capture
        Args:

        Returns:
            int: Number of packets with missing ICMP IPs
            int: Number of all ICMP IPs
        '''
        # get all IPs from ICMP packets
        icmp_ips = self.functions.get_icmp_ips()

        # get all IPs from other packets
        other_ips = self.functions.get_non_icmp_ips()

        # check if all ICMP IPs are in other IPs
        failed = 0
        for ip in icmp_ips:
            if ip not in other_ips and ip != '0.0.0.0':
                failed += 1

        return failed, len(icmp_ips)
    
    def get_inconsistent_user_agent(self):
        """
        User agent should be the same in one communication channel for the whole communication
        Args:

        Returns:
            int: Number of packets with inconsistent user agent
            int: Number of all communication channels
        """
        channels = self.functions.get_communication_channels_triplets(self.session.query(
            Packet.ip_src,
            Packet.ip_dst,
            Packet.user_agent,
            Packet.port_dst
            ).filter(
            and_(
                Packet.id_pcap == self.id_pcap,
                Packet.user_agent.isnot(None),
                Packet.type == 2048
            )
        ).all())

        failed = 0

        for channel in channels:
            user_agents = set()
            for i in range(len(channels[channel])):
                if channels[channel][i].user_agent is not None:
                    user_agents.add(channels[channel][i].user_agent)
            if len(user_agents) > 1:
                failed += 1

        return failed, len(channels)

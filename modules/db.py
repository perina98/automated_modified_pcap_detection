##################################################
## This modules ensures database exists and loads pcap packets to this database
##################################################
## File: db.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import os
import json
from scapy.all import *
from scapy.layers.tls import *

from database import Packet, Pcap

class Database():
    '''
    Main database handler class
    Args:

    Returns:
    '''
    def ensure_db(self, engine, database):
        '''
        Ensure database exists and create tables
        Args:
            engine: sqlalchemy engine
            database: database path

        Returns:
            None
        '''
        if os.path.exists(database):
            os.remove(database)
        Packet.metadata.create_all(engine)
        Pcap.metadata.create_all(engine)

    def save_pcap(self, session, path):
        '''
        Save pcap file info to database
        Args:
            session: sqlalchemy session
            path: path to pcap file

        Returns:
            id_pcap: id of saved pcap file
        '''
        new_pcap = Pcap(path=path)
        session.add(new_pcap)
        session.commit()
        return new_pcap.id_pcap

    def save_packet(self, session, id_pcap, pkt):
        '''
        Save packet info to database
        Args:
            session: sqlalchemy session
            id_pcap: id of pcap file
            pkt: scapy packet

        Returns:
            None
        '''
        load_layer('tls')
        # packet data structure
        pkt_data = {
            'protocol': None,
            'type': None,
            'ip_src': None,
            'ip_dst': None,
            'port_src': None,
            'port_dst': None,
            'eth_src': None,
            'eth_dst': None,
            'length': None,
            'seq': None,
            'ack': None,
            'window': None,
            'dns': None,
            'arp_op': None,
            'arp_ip_src': None,
            'arp_ip_dst': None,
            'ttl': None,
            'mss': None,
            'tls_msg_type': None,
            'tls_ciphers': None,
            'tcp_segment_len': None,
            'tcp_flags': None,
            'dhcp_yiaddr': None,
            'icmp_type': None,
            'user_agent': None,
            'ip_flag': None,
            'ip_fragment_offset': None,
            'ip_identification': None,
            'is_ftp': None
        }

        # save IP layer data
        if pkt.haslayer(IP):
            pkt_data['protocol'] = pkt[IP].proto
            pkt_data['ip_src'] = pkt[IP].src
            pkt_data['ip_dst'] = pkt[IP].dst
            pkt_data['ttl'] = pkt[IP].ttl
            pkt_data['ip_flag'] = int(pkt[IP].flags)
            pkt_data['ip_fragment_offset'] = pkt[IP].frag
            pkt_data['ip_identification'] = pkt[IP].id
            
            # save TCP layer data
            if pkt.haslayer(TCP):
                pkt_data['port_src'] = pkt[TCP].sport
                pkt_data['port_dst'] = pkt[TCP].dport
                pkt_data['seq'] = pkt[TCP].seq
                pkt_data['ack'] = pkt[TCP].ack
                pkt_data['window'] = pkt[TCP].window
                pkt_data['tcp_segment_len'] = len(pkt[TCP]) - pkt[TCP].dataofs * 4 if (len(pkt[TCP]) - pkt[TCP].dataofs * 4) > 0 else 0
                pkt_data['tcp_flags'] = str(pkt[TCP].flags)
                mss = list(filter(lambda t: t[0] == 'MSS', pkt[TCP].options))
                if mss:
                    pkt_data['mss'] = mss[0][1]

                if (pkt_data['port_src'] == 21 or pkt_data['port_dst'] == 21) and pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load.decode("utf-8", "ignore").lower()
                    if "ftp" in raw_data:
                        pkt_data['is_ftp'] = True

            # save UDP layer data
            elif pkt.haslayer(UDP):
                pkt_data['port_src'] = pkt[UDP].sport
                pkt_data['port_dst'] = pkt[UDP].dport

        # save DNS layer data
        if pkt.haslayer(DNS):
            dns_data = {
                'id': pkt[DNS].id,
                'qd': None,
                'an': None,
            }

            an = None

            if pkt[DNS].qd:
                dns_data['qd'] = { 'qname': pkt[DNS].qd.qname.decode(), 'qtype': pkt[DNS].qd.qtype }

            if pkt[DNS].an:
                an = []
                
                for i in range(pkt[DNS].ancount):
                    ans = pkt[DNS].an[i]
                    try:
                        rrname = ans.rrname
                        rdata = ans.rdata
                        ptype = ans.type
                    except AttributeError:
                        continue
                    try:
                        if type(ans.rrname) is bytes:
                            rrname = ans.rrname.decode()
                        
                        if type(ans.rdata) is bytes:
                            rdata = ans.rdata.decode()

                        if type(ans.rdata) is list:
                            srdata = []
                            for item in ans.rdata:
                                if type(item) is bytes:
                                    srdata.append(item.decode())
                                else:
                                    srdata.append(item)
                            rdata = srdata
                    except UnicodeDecodeError:
                        continue

                    an.append({ 'rrname': rrname, 'rdata': rdata, 'type': ptype })

            dns_data['an'] = an
            
            try:
                pkt_data['dns'] = json.dumps(dns_data)
            except:
                pass

        try:
            pkt_data['type'] = pkt.type
            pkt_data['eth_src'] = pkt[Ether].src
            pkt_data['eth_dst'] = pkt[Ether].dst
        except (AttributeError, IndexError):
            pass
        
        # save DHCP / BOOTP layer data
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            pkt_data['dhcp_yiaddr'] = pkt[BOOTP].yiaddr

        # save ARP layer data
        if pkt.haslayer(ARP):
            pkt_data['arp_op'] = pkt[ARP].op
            pkt_data['arp_ip_src'] = pkt[ARP].psrc
            pkt_data['arp_ip_dst'] = pkt[ARP].pdst

        # save TLS layer data
        if pkt.haslayer(TLS):
            try:
                pkt_data['tls_msg_type'] = pkt[TLS].msg[0].msgtype
                if pkt[TLS].msg[0].msgtype == 1:
                    pkt_data['tls_ciphers'] = json.dumps(pkt[TLS].msg[0].ciphers)
                if pkt[TLS].msg[0].msgtype == 2:
                    pkt_data['tls_ciphers'] = json.dumps(pkt[TLS].msg[0].cipher)
            except (AttributeError, IndexError):
                pass
        
        # save ICMP layer data
        if pkt.haslayer(ICMP):
            pkt_data['icmp_type'] = pkt[ICMP].type

        # save HTTP layer data
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            if "HTTP" in str(raw_data):
                http_headers = str(raw_data).split("\\r\\n\\r\\n")[0]
                user_agent = None
                for line in http_headers.split("\\r\\n"):
                    if "User-Agent:" in line:
                        user_agent = line.split("User-Agent: ")[1]
                        break
                pkt_data['user_agent'] = user_agent



        pkt_data['length'] = len(pkt)
        
        # build Packet object
        new_packet = Packet(
            packet_timestamp=pkt.time,
            type=pkt_data['type'],
            protocol=pkt_data['protocol'],
            ip_src=pkt_data['ip_src'],
            ip_dst=pkt_data['ip_dst'],
            port_src=pkt_data['port_src'],
            port_dst=pkt_data['port_dst'],
            seq=pkt_data['seq'],
            ack=pkt_data['ack'],
            tcp_segment_len=pkt_data['tcp_segment_len'],
            tcp_flags=pkt_data['tcp_flags'],
            window=pkt_data['window'],
            eth_src=pkt_data['eth_src'],
            eth_dst=pkt_data['eth_dst'],
            length=pkt_data['length'],
            dns=pkt_data['dns'],
            arp_op=pkt_data['arp_op'],
            arp_ip_src=pkt_data['arp_ip_src'],
            arp_ip_dst=pkt_data['arp_ip_dst'],
            ttl=pkt_data['ttl'],
            mss=pkt_data['mss'],
            tls_msg_type=pkt_data['tls_msg_type'],
            tls_ciphers=pkt_data['tls_ciphers'],
            dhcp_yiaddr=pkt_data['dhcp_yiaddr'],
            icmp_type=pkt_data['icmp_type'],
            user_agent=pkt_data['user_agent'],
            ip_flag=pkt_data['ip_flag'],
            ip_fragment_offset=pkt_data['ip_fragment_offset'],
            ip_identification=pkt_data['ip_identification'],
            is_ftp=pkt_data['is_ftp'],
            id_pcap=id_pcap
        )
        session.add(new_packet)

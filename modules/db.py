##################################################
## This modules ensures database and loads pcap packets to this database
##################################################
## File: db.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
from scapy.layers.tls import *
from tqdm import tqdm

class Database():
    # create database if not exists
    def ensure_db(self,cursor):
        cursor.execute('''DROP TABLE IF EXISTS pcap''')
        cursor.execute('''DROP TABLE IF EXISTS packet''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS pcap (
                    id_pcap INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT
                    )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS packet (
                    id_packet INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_timestamp TEXT,
                    type INTEGER,
                    protocol INTEGER,
                    ip_src TEXT,
                    ip_dst TEXT,
                    port_src INTEGER,
                    port_dst INTEGER,
                    eth_src TEXT,
                    eth_dst TEXT,
                    tcp_checksum TEXT,
                    udp_checksum TEXT,
                    ip_checksum TEXT,
                    icmp_checksum TEXT,
                    tcp_checksum_calculated TEXT,
                    udp_checksum_calculated TEXT,
                    ip_checksum_calculated TEXT,
                    icmp_checksum_calculated TEXT,
                    id_pcap INTEGER,
                    FOREIGN KEY (id_pcap) REFERENCES pcap(id_pcap)
                    )''')

    def get_packets(self, id_pcap, cursor, rows = ["*"]):
        query = "SELECT * FROM packet WHERE id_pcap = ?"
        query = query.replace("*", ",".join(rows))
        cursor.execute(query, (id_pcap,))
        return cursor.fetchall()
        
    def load(self,detector,pcap_path, pcap_len):
        detector.log.debug("Loading pcap file %s", pcap_path)

        detector.db_cursor.execute("INSERT INTO pcap (path) VALUES (?)", (pcap_path,))

        pcap_id = detector.db_cursor.lastrowid

        pkts = PcapReader(pcap_path)
        for pkt in tqdm(pkts, desc="Loading pcap file", unit=" packets", total=pcap_len):
            pkt_data = {
                'protocol': None,
                'type': None,
                'ip_src': None,
                'ip_dst': None,
                'port_src': None,
                'port_dst': None,
                'eth_src': None,
                'eth_dst': None,
                'tcp_checksum': None,
                'udp_checksum': None,
                'ip_checksum': None,
                'icmp_checksum': None,
                'tcp_checksum_calculated': None,
                'udp_checksum_calculated': None,
                'ip_checksum_calculated': None,
                'icmp_checksum_calculated': None
            }

            if pkt.haslayer(IP):
                pkt_data['protocol'] = pkt[IP].proto
                pkt_data['ip_src'] = pkt[IP].src
                pkt_data['ip_dst'] = pkt[IP].dst

                if pkt.haslayer(TCP):
                    pkt_data['port_src'] = pkt[TCP].sport
                    pkt_data['port_dst'] = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    pkt_data['port_src'] = pkt[UDP].sport
                    pkt_data['port_dst'] = pkt[UDP].dport

            pkt_data['type'] = pkt.type
            pkt_data['eth_src'] = pkt[Ether].src
            pkt_data['eth_dst'] = pkt[Ether].dst

            all_checksums = detector.checksums.get_checksums(pkt)
            pkt_data['tcp_checksum'] = all_checksums['tcp_checksum']
            pkt_data['udp_checksum'] = all_checksums['udp_checksum']
            pkt_data['ip_checksum'] = all_checksums['ip_checksum']
            pkt_data['icmp_checksum'] = all_checksums['icmp_checksum']
            pkt_data['tcp_checksum_calculated'] = all_checksums['tcp_checksum_calculated']
            pkt_data['udp_checksum_calculated'] = all_checksums['udp_checksum_calculated']
            pkt_data['ip_checksum_calculated'] = all_checksums['ip_checksum_calculated']
            pkt_data['icmp_checksum_calculated'] = all_checksums['icmp_checksum_calculated']

            detector.db_cursor.execute("""INSERT INTO packet (packet_timestamp, 
                                    protocol, 
                                    type,
                                    ip_src, 
                                    ip_dst, 
                                    eth_src,
                                    eth_dst,
                                    port_src, 
                                    port_dst,
                                    tcp_checksum,
                                    udp_checksum,
                                    ip_checksum,
                                    icmp_checksum,
                                    tcp_checksum_calculated,
                                    udp_checksum_calculated,
                                    ip_checksum_calculated,
                                    icmp_checksum_calculated,
                                    id_pcap)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (str(pkt.time),
                                    pkt_data['protocol'],
                                    pkt_data['type'],
                                    pkt_data['ip_src'],
                                    pkt_data['ip_dst'],
                                    pkt_data['eth_src'],
                                    pkt_data['eth_dst'],
                                    pkt_data['port_src'],
                                    pkt_data['port_dst'],
                                    pkt_data['tcp_checksum'],
                                    pkt_data['udp_checksum'],
                                    pkt_data['ip_checksum'],
                                    pkt_data['icmp_checksum'],
                                    pkt_data['tcp_checksum_calculated'],
                                    pkt_data['udp_checksum_calculated'],
                                    pkt_data['ip_checksum_calculated'],
                                    pkt_data['icmp_checksum_calculated'],
                                    pcap_id)
                            )

        detector.db_conn.commit()

        detector.log.debug("Finished loading pcap file %s", pcap_path)

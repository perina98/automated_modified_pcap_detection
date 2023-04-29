##################################################
## SQL tables for database
##################################################
## File: tables.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from sqlalchemy import Column, Integer, String, ForeignKey, Double
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Packet(Base):
    '''
    Packet class that represents packet table in database
    Args:
        Base: sqlalchemy base class

    Returns:
    '''
    __tablename__ = 'packet'
    id_packet = Column(Integer, primary_key=True)
    packet_timestamp = Column(Double)
    type = Column(Integer)
    protocol = Column(Integer)
    ip_src = Column(String)
    ip_dst = Column(String)
    port_src = Column(Integer)
    port_dst = Column(Integer)
    seq = Column(Integer)
    ack = Column(Integer)
    tcp_segment_len = Column(Integer)
    tcp_flags = Column(String)
    window = Column(Integer)
    eth_src = Column(String)
    eth_dst = Column(String)
    dns = Column(String)
    arp_op = Column(Integer)
    arp_ip_src = Column(String)
    arp_ip_dst = Column(String)
    ttl = Column(Integer)
    mss = Column(Integer)
    tls_msg_type = Column(Integer)
    tls_ciphers = Column(String)
    dhcp_yiaddr = Column(String)
    icmp_type = Column(Integer)
    user_agent = Column(String)
    ip_flag = Column(Integer)
    ip_fragment_offset = Column(Integer)
    ip_identification = Column(Integer)
    length = Column(Integer)
    is_ftp = Column(Integer)
    id_pcap = Column(Integer, ForeignKey('pcap.id_pcap'))
    pcap = relationship("Pcap", back_populates="packets")

class Pcap(Base):
    '''
    Pcap class that represents pcap table in database
    Args:
        Base: sqlalchemy base class

    Returns:
    '''
    __tablename__ = 'pcap'
    id_pcap = Column(Integer, primary_key=True)
    path = Column(String)
    packets = relationship("Packet", order_by=Packet.id_packet, back_populates="pcap")

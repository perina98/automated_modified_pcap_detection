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
    window = Column(Integer)
    eth_src = Column(String)
    eth_dst = Column(String)
    id_pcap = Column(Integer, ForeignKey('pcap.id_pcap'))
    length = Column(Integer)
    dns = Column(String)
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

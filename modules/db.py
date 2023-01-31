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

import os
from scapy.all import *
from scapy.layers.tls import *
from sqlalchemy import Column, Integer, String, ForeignKey, Double
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Pcap(Base):
    __tablename__ = 'pcap'
    id_pcap = Column(Integer, primary_key=True)
    path = Column(String)

class Packet(Base):
    __tablename__ = 'packet'
    id_packet = Column(Integer, primary_key=True)
    packet_timestamp = Column(Double)
    type = Column(Integer)
    protocol = Column(Integer)
    ip_src = Column(String)
    ip_dst = Column(String)
    port_src = Column(Integer)
    port_dst = Column(Integer)
    eth_src = Column(String)
    eth_dst = Column(String)
    id_pcap = Column(Integer, ForeignKey('pcap.id_pcap'))
    length = Column(Integer)
    pcap = relationship("Pcap", back_populates="packets")

class Database():
    # create database if not exists
    def ensure_db(self, engine, database):
        if os.path.exists(database):
            os.remove(database)
        Base.metadata.create_all(engine)
        Pcap.packets = relationship("Packet", order_by=Packet.id_packet, back_populates="pcap")

    def save_pcap(self, session, path):
        new_pcap = Pcap(path=path)
        session.add(new_pcap)
        session.commit()
        return new_pcap.id_pcap

    def save_packet(self, session, id_pcap, pkt):
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
        pkt_data['length'] = len(pkt)
        
        new_packet = Packet(
            packet_timestamp=pkt.time,
            type=pkt_data['type'],
            protocol=pkt_data['protocol'],
            ip_src=pkt_data['ip_src'],
            ip_dst=pkt_data['ip_dst'],
            port_src=pkt_data['port_src'],
            port_dst=pkt_data['port_dst'],
            eth_src=pkt_data['eth_src'],
            eth_dst=pkt_data['eth_dst'],
            length=pkt_data['length'],
            id_pcap=id_pcap
        )
        session.add(new_packet)

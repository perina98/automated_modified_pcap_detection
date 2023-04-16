##################################################
## This module checks internet layer related information for any inconsistencies
##################################################
## File: internet_layer.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

from scapy.all import *
import modules.functions as functions

class InternetLayer():
    '''
    Class for checking internet layer for any inconsistencies
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
        self.functions =  functions.Functions(id_pcap, session)
import os
import subprocess
import copy
from scapy.all import *

DIR = 'dataset'

# use scapy to check if the packet is modified
def check_packet(pkt):
    # calculate the checksum of the packet
    # if the checksum is not the same as the original packet, the packet is modified
    if pkt.haslayer(TCP):
        old_checksum = pkt[TCP].chksum
        del pkt[TCP].chksum
        new_checksum = pkt[TCP].chksum
        if old_checksum != new_checksum:
            return True

    if pkt.haslayer(UDP):
        old_checksum = pkt[UDP].chksum
        del pkt[UDP].chksum
        new_checksum = pkt[UDP].chksum
        if old_checksum != new_checksum:
            return True
    
    if pkt.haslayer(IP):
        old_checksum = pkt[IP].chksum
        del pkt[IP].chksum
        new_checksum = pkt[IP].chksum
        if old_checksum != new_checksum:
            return True

    return False

# read pcap file from DIR and check if it is modified
def check_pcap(pcap):
    pkts = rdpcap(pcap)
    modified_pkts = 0
    for pkt in pkts:
        if check_packet(pkt):
            modified_pkts += 1
        
    print('Modified packets in pcap file '+ pcap +': '+str(modified_pkts)+'/'+str(len(pkts)))


if __name__ == '__main__':
    # get list of pcap files in DIR
    pcaps = os.listdir(DIR)
    # make sure pcaps are only pcap files
    pcaps = [pcap for pcap in pcaps if pcap.endswith('.pcap')]

    # check each pcap file
    for pcap in pcaps:
        check_pcap(DIR+'/'+pcap)



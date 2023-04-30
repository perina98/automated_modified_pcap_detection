#! /usr/bin/env python3
# -*- coding: utf-8 -*-

##################################################
## Script for creating dataset files from a given input file
##################################################
## File: createdataset.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import os
import subprocess
import copy
import logging
import random
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.all import ICMP, IP, sr1
from scapy.layers.tls import *

random.seed(1)

INFILE = 'static/input.pcap'
DATASET_DIR = 'dataset'
PREFIX = 'pcap_output_'

def ensure_dir():
    '''
    Check if output directory exists, if not create it
    Args:

    Returns:
    '''
    if os.path.isdir(DATASET_DIR):
        print('Output directory already exists: '+DATASET_DIR)
        print('Purging all files in output directory')
        subprocess.run(['rm -f '+DATASET_DIR+'/*'], shell=True)
    else:
        print('Creating directory: '+DATASET_DIR)
        subprocess.run(['mkdir -p '+DATASET_DIR], shell=True)

def ensure_file():
    '''
    Check if input file exists
    Args:

    Returns:
    '''
    print('Checking for input file: '+INFILE)
    if not os.path.isfile(INFILE):
        print('Input file input.pcap does not exist in the static directory')
        exit(1)

def adjust_paths():
    '''
    Adjust paths if script is run from the static directory
    Args:

    Returns:
    '''
    global INFILE
    global DATASET_DIR
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # get the current working directory
    cwd = os.getcwd()

    # compare the two directories
    if script_dir == cwd:
        print("The current directory is the same as the script directory. Adjusting paths accordingly.")
        INFILE = '../'+INFILE
        DATASET_DIR = '../'+DATASET_DIR

def run_all():
    '''
    Run all methods to create datasets
    Args:

    Returns:
    '''
    print("Loading input file: "+INFILE)
    pkts = rdpcap(INFILE)
    orig = copy.deepcopy(pkts)

    make_dataset_tcprewrite()
    make_dataset_scapy(pkts)
    pkts = copy.deepcopy(orig)
    make_dataset_scapy_specific(pkts)
    pkts = copy.deepcopy(orig)
    make_dataset_scapy_advanced(pkts)

def make_dataset_tcprewrite():
    '''
    Create multiple dataset files using tcprewrite and python subprocess
    Args:

    Returns:
    '''
    print('')
    print('Creating dataset files using tcprewrite')
    print('')

    print('1. Change IP addresses from 4.122.55.7 to 10.11.12.13, port 443 to 4')
    subprocess.run(['tcprewrite', '--pnat=4.122.55.7:10.11.12.13', '--portmap=443:4', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'01.pcap'])
    print('2. Randomize IP addresses using seed 1234')
    subprocess.run(['tcprewrite', '--seed=1234', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'02.pcap'])
    print('3. Randomize IP addresses using seed 1234, change MTU to 60, change TTL to 63:3, truncate to mtu')
    subprocess.run(['tcprewrite', '--seed=1234', '--mtu-trunc', '--ttl=63:3', '--mtu=60', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'03.pcap'])
    print('4. Randomize IP addresses using seed 1234, change MTU to 160, change TTL to 63:3, truncate to mtu')
    subprocess.run(['tcprewrite', '--seed=1234', '--mtu-trunc', '--ttl=63:3', '--mtu=160', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'04.pcap'])

def make_dataset_scapy(pkts):
    '''
    Create basic dataset files using scapy
    Args:
        pkts: list of packets
    Returns:
    '''
    orig = copy.deepcopy(pkts)
    random_mac = RandMAC()
    random_ip = RandIP()

    print('')
    print('Creating dataset files using scapy')
    print('')

    print('5. Randomize source MAC addresses')
    for pkt in pkts:
        pkt.src = random_mac
    wrpcap(DATASET_DIR+'/'+PREFIX+'05.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('6. Randomize destination IP addresses')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt[IP].dst = random_ip
    wrpcap(DATASET_DIR+'/'+PREFIX+'06.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('7. Randomize IP addresses')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt[IP].src = random_ip
            pkt[IP].dst = random_ip
    wrpcap(DATASET_DIR+'/'+PREFIX+'07.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('8. Change src IP from 4.122.55.7 to 11.12.13.14')
    for pkt in pkts:
        if pkt.haslayer(IP) and pkt[IP].src == '4.122.55.7':
            pkt[IP].src = '11.12.13.14'
    wrpcap(DATASET_DIR+'/'+PREFIX+'08.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('9. Change IP from 4.122.55.7 to 11.12.13.14')
    for pkt in pkts:
        pkt.dst = random_mac
        if pkt.haslayer(IP):
            if pkt[IP].src == '4.122.55.7':
                pkt[IP].src = '4.122.55.198'
    wrpcap(DATASET_DIR+'/'+PREFIX+'09.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('10. Change src IP 1.1.1.1 and protocol to 17 for ip.dst == 4.122.55.2')
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].dst == '4.122.55.2':
                pkt[IP].src = '1.1.1.1'
                pkt[IP].proto = 17
        
    wrpcap(DATASET_DIR+'/'+PREFIX+'10.pcap', pkts)
    pkts = copy.deepcopy(orig)


    print('11. Change src IP 1.1.1.1 and protocol to 17 for ip.dst == 4.122.55.2')
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.4.2.27' or pkt[IP].src == '10.2.2.27':
                pkt[IP].proto = 17
                pkt.src = 'ff:ff:ff:ff:ff:ff'
                if pkt.haslayer(TCP):
                    pkt[TCP].sport = 443
                    pkt[TCP].dport = 4
            if pkt[IP].dst == '10.4.2.27' or pkt[IP].dst == '10.2.2.27':
                pkt[IP].proto = 1
                pkt.src = 'ff:fa:fa:fa:fa:ff'
                if pkt.haslayer(UDP):
                    pkt[UDP].sport = 53
                    pkt[UDP].dport = 4

    wrpcap(DATASET_DIR+'/'+PREFIX+'11.pcap', pkts)
    pkts = copy.deepcopy(orig)


def make_dataset_scapy_specific(pkts):
    '''
    Create dataset files specific to detection methods in detector class using scapy
    Args:
        pkts: list of packets
    Returns:
    '''
    orig = copy.deepcopy(pkts)
    random_ip = RandIP()

    print('')
    print('Creating dataset files specific to detection methods using scapy')
    print('')

    print('12. Change DNS answers to specific IP')
    for pkt in pkts:
        if pkt.haslayer(DNS) and pkt[DNS].an:
            for i in range(pkt[DNS].ancount):
                if pkt[DNS].an[i].type == 1:
                    pkt[DNS].an[i].rdata = b'1.1.1.1'
            del pkt['IP'].len
            del pkt['IP'].chksum
            del pkt['UDP'].len
            del pkt['UDP'].chksum
            pkt = Ether(pkt.build())
    wrpcap(DATASET_DIR+'/'+PREFIX+'12.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('13. Malform http packets by trying to change user agent')
    for pkt in pkts:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            if "HTTP" in str(raw_data):
                http_headers = str(raw_data).split("\\r\\n\\r\\n")[0]
                for line in http_headers.split("\\r\\n"):
                    if "User-Agent:" in line:
                        randnum = random.randint(0, 64)
                        http_headers = http_headers.replace(line, 'User-Agent: Mobilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.'+str(randnum)+' (KHTML, like Gecko)')
                        break
                pkt[Raw].load = http_headers + "\\r\\n\\r\\n" + str(raw_data).split("\\r\\n\\r\\n")[1]
    wrpcap(DATASET_DIR+'/'+PREFIX+'13.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('14. Manipulate the ciphersuite')
    for pkt in pkts:
        if pkt.haslayer(TLS):
            try:
                if pkt[TLS].msg[0].msgtype == 1:
                    ciphers = pkt[TLS].msg[0].ciphers
                    # remove random cipher
                    del ciphers[random.randint(0, len(ciphers)-1)]
                    del ciphers[random.randint(0, len(ciphers)-2)]
                    del ciphers[random.randint(0, len(ciphers)-3)]
                    # add random cipher
                    ciphers.append(0xf000)
                if pkt[TLS].msg[0].msgtype == 2:
                    pkt[TLS].msg[0].cipher = 0x0000
            except (AttributeError, IndexError):
                pass
    wrpcap(DATASET_DIR+'/'+PREFIX+'14.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('15. Randomize mss, window size, ttl and ip id')
    for pkt in pkts:
        if pkt.haslayer(TCP):
            pkt[TCP].window = random.randint(0, 65535)
            pkt[TCP].options = [('MSS', random.randint(0, 65535))]
        if pkt.haslayer(IP):
            pkt[IP].ttl = random.randint(0, 255)
            pkt[IP].id = random.randint(0, 65535)
    wrpcap(DATASET_DIR+'/'+PREFIX+'15.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('16. Change ip addresses for ICMP packets and add some more ICMP packets')
    pkts_list = []
    for pkt in pkts:
        if pkt.haslayer(ICMP):
            pkt2 = copy.deepcopy(pkt)
            pkt2[IP].src = random_ip
            pkt[IP].src = random_ip
            pkt2[IP].dst = random_ip
            pkt[IP].dst = random_ip
            pkts_list.append(pkt2)
    pkts.extend(pkts_list)
    wrpcap(DATASET_DIR+'/'+PREFIX+'16.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('17. Remove all ARP traffic')
    pktlist = []
    for pkt in pkts:
        if not pkt.haslayer(ARP):
            pktlist.append(pkt)
    wrpcap(DATASET_DIR+'/'+PREFIX+'17.pcap', pktlist)
    pkts = copy.deepcopy(orig)

    print('18. Mismatch DNS query and response')
    for pkt in pkts:
        if pkt.haslayer(DNS):
            if pkt[DNS].qd and not pkt[DNS].an:
                pkt[DNS].qd.qname = b'www.googleees.com'
    wrpcap(DATASET_DIR+'/'+PREFIX+'18.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('19. Mismatch DNS answer stack')
    for pkt in pkts:
        if pkt.haslayer(DNS):
            if pkt[DNS].an:
                for i in range(pkt[DNS].ancount):
                    ans = pkt[DNS].an[i]
                    if ans.type == 5:
                        random_str = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
                        pkt[DNS].an[i].rdata = random_str

                pkt = Ether(pkt.build())

    wrpcap(DATASET_DIR+'/'+PREFIX+'19.pcap', pkts)
    pkts = copy.deepcopy(orig)



def make_dataset_scapy_advanced(pkts):
    '''
    Create advanced dataset files using scapy
    Args:
        pkts: list of packets
    Returns:
    '''
    orig = copy.deepcopy(pkts)

    print('')
    print('Creating advanced dataset files using scapy')
    print('')

    print('20. Mismatch DNS')
    for pkt in pkts:
        if pkt.haslayer(DNS):
            if pkt[DNS].qd and not pkt[DNS].an:
                pkt[DNS].qd.qname = b'www.googleees.com'
            if pkt[DNS].an:
                for i in range(pkt[DNS].ancount):
                    ans = pkt[DNS].an[i]
                    if ans.type == 5:
                        random_str = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
                        pkt[DNS].an[i].rdata = random_str

                del pkt['IP'].len
                del pkt['UDP'].len
                pkt = Ether(pkt.build())
    wrpcap(DATASET_DIR+'/'+PREFIX+'20.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('21. Malform packet payload for IP 4.122.55.7')
    for pkt in pkts:
        if pkt.haslayer(IP):
            if (pkt[IP].src == '4.122.55.7' or pkt[IP].dst == '4.122.55.7') and pkt.haslayer(Raw):
                pkt[Raw].load = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    wrpcap(DATASET_DIR+'/'+PREFIX+'21.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('22. Swap IP addresses, 4.122.55.7 <-> 13.107.21.200')
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '4.122.55.7':
                pkt[IP].src = '13.107.21.200'
            elif pkt[IP].src == '13.107.21.200':
                pkt[IP].src = '4.122.55.7'
            if pkt[IP].dst == '4.122.55.7':
                pkt[IP].dst = '13.107.21.200'
            elif pkt[IP].dst == '13.107.21.200':
                pkt[IP].dst = '4.122.55.7'
    wrpcap(DATASET_DIR+'/'+PREFIX+'22.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('23. Remove all traffic for 4.122.55.7')
    pktlist = []
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src != '4.122.55.7' and pkt[IP].dst != '4.122.55.7':
                pktlist.append(pkt)
    wrpcap(DATASET_DIR+'/'+PREFIX+'23.pcap', pktlist)
    pkts = copy.deepcopy(orig)
    
    print('24. Limit TCP payload size to 10 bytes')
    for pkt in pkts:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            pkt[Raw].load = pkt[Raw].load[:10]
    wrpcap(DATASET_DIR+'/'+PREFIX+'24.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('25. Remove all TCP traffic')
    pktlist = []
    for pkt in pkts:
        if not pkt.haslayer(TCP):
            pktlist.append(pkt)
    wrpcap(DATASET_DIR+'/'+PREFIX+'25.pcap', pktlist)
    pkts = copy.deepcopy(orig)

    print('26. Set all ack numbers to 10')
    for pkt in pkts:
        if pkt.haslayer(TCP):
            pkt[TCP].ack = 10
    wrpcap(DATASET_DIR+'/'+PREFIX+'26.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('27. Change wirelen to 555')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt.wirelen = 555
    wrpcap(DATASET_DIR+'/'+PREFIX+'27.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('28. Remove packet payload')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt.remove_payload()
    wrpcap(DATASET_DIR+'/'+PREFIX+'28.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('29. Malform IP header so that it is invalid, random data')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt[IP].version = 5
            pkt[IP].ihl = 5
            pkt[IP].tos = 5
            pkt[IP].len = 5
            pkt[IP].id = 5
            pkt[IP].flags = 5
            pkt[IP].frag = 5
            pkt[IP].ttl = 5
            pkt[IP].proto = 5
            pkt[IP].chksum = 5
            pkt[IP].src = '5.5.5.5'
            pkt[IP].dst = '5.5.5.5'
    wrpcap(DATASET_DIR+'/'+PREFIX+'29.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('30. Malform packet raw layer payload')
    for pkt in pkts:
        if pkt.haslayer(Raw):
            pkt[Raw].load = b'5'
    wrpcap(DATASET_DIR+'/'+PREFIX+'30.pcap', pkts)
    pkts = copy.deepcopy(orig)


if __name__ == '__main__':
    adjust_paths()
    ensure_file()
    ensure_dir()
    load_layer('tls')
    run_all()

    print("")
    print("Done! Dataset files are located in ./" + DATASET_DIR + "/ directory")
    print("")

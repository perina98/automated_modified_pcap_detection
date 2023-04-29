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
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.tls import *

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

    #make_dataset_tcprewrite()
    #make_dataset_scapy(pkts)
    #pkts = copy.deepcopy(orig)
    make_dataset_scapy_specific(pkts)
    #pkts = copy.deepcopy(orig)
    #make_dataset_scapy_specific(pkts)

def make_dataset_tcprewrite():
    '''
    Create multiple dataset files using tcprewrite and python subprocess
    Args:

    Returns:
    '''
    print('')
    print('Creating dataset files using tcprewrite')
    print('')

    print('1. Change IP addresses from 4.122.55.7 to 10.11.12.13')
    subprocess.run(['tcprewrite', '--pnat=4.122.55.7:10.11.12.13', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'01.pcap'])
    print('2. Randomize IP addresses using seed 1234')
    subprocess.run(['tcprewrite', '--seed=1234', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'02.pcap'])
    print('3. Randomize IP addresses using seed 1234, change MTU to 60, change TTL to 63:3, truncate to mtu')
    subprocess.run(['tcprewrite', '--seed=1234', '--mtu-trunc', '--ttl=63:3', '--mtu=60', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'03.pcap'])
    print('4. Randomize IP addresses using seed 1234, change MTU to 160, change TTL to 63:3, truncate to mtu')
    subprocess.run(['tcprewrite', '--seed=1234', '--mtu-trunc', '--ttl=63:3', '--mtu=160', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'04.pcap'])
    print('5. Change ports from 80 to 4 and 443 to 4')
    subprocess.run(['tcprewrite', '--portmap=80:4,443:4', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'05.pcap'])

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
    print('6. Randomize source MAC addresses')
    for pkt in pkts:
        pkt.src = random_mac
    wrpcap(DATASET_DIR+'/'+PREFIX+'06.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('7. Randomize destination IP addresses')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt[IP].dst = random_ip
    wrpcap(DATASET_DIR+'/'+PREFIX+'07.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('8. Randomize IP addresses')
    for pkt in pkts:
        if pkt.haslayer(IP):
            pkt[IP].src = random_ip
            pkt[IP].dst = random_ip
    wrpcap(DATASET_DIR+'/'+PREFIX+'08.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('9. Change src IP from 4.122.55.7 to 11.12.13.14')
    for pkt in pkts:
        if pkt.haslayer(IP) and pkt[IP].src == '4.122.55.7':
            pkt[IP].src = '11.12.13.14'
    wrpcap(DATASET_DIR+'/'+PREFIX+'09.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('10. Change IP from 4.122.55.7 to 11.12.13.14')
    for pkt in pkts:
        pkt.dst = random_mac
        if pkt.haslayer(IP):
            if pkt[IP].src == '4.122.55.7':
                pkt[IP].src = '4.122.55.198'
    wrpcap(DATASET_DIR+'/'+PREFIX+'10.pcap', pkts)
    pkts = copy.deepcopy(orig)

    print('11. Change src IP 1.1.1.1 and protocol to 17 for ip.dst == 4.122.55.2')
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].dst == '4.122.55.2':
                pkt[IP].src = '1.1.1.1'
                pkt[IP].proto = 17
        
    wrpcap(DATASET_DIR+'/'+PREFIX+'11.pcap', pkts)
    pkts = copy.deepcopy(orig)


    print('12. Change src IP 1.1.1.1 and protocol to 17 for ip.dst == 4.122.55.2')
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

    wrpcap(DATASET_DIR+'/'+PREFIX+'12.pcap', pkts)
    pkts = copy.deepcopy(orig)


def make_dataset_scapy_specific(pkts):
    '''
    Create dataset files specific to detection methods in detector class using scapy
    Args:
        pkts: list of packets
    Returns:
    '''
    orig = copy.deepcopy(pkts)

    print('')
    print('Creating dataset files specific to detection methods using scapy')
    print('')

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

if __name__ == '__main__':
    adjust_paths()
    ensure_file()
    ensure_dir()
    load_layer('tls')
    run_all()

    print("")
    print("Done! Dataset files are located in ./" + DATASET_DIR + "/ directory")
    print("")

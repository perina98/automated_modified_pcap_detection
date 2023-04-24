#! /usr/bin/env python3
# -*- coding: utf-8 -*-

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

def make_dataset_tcprewrite():
    print('Creating tcprewrite dataset')
    #1 change ip address
    subprocess.run(['tcprewrite', '--pnat=10.3.4.42:10.152.1.200', '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'01.pcap'])

    #2 change ports
    subprocess.run(['tcprewrite', '--portmap=80:8080,22:8022', '--fixcsum' , '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'02.pcap'])

    #3 change ip address and ports
    subprocess.run(['tcprewrite', '--pnat=10.2.2.27:10.3.8.88', '--portmap=22:10222,443:60123', '--fixcsum' , '--infile=./'+INFILE, '--outfile='+DATASET_DIR+'/'+PREFIX+'03.pcap'])

def make_dataset_scapy(pkts):
    print('Creating scapy dataset')

    orig = copy.deepcopy(pkts)
    
    #4 change dns domain in dns query
    for pkt in pkts:
        if pkt.haslayer(DNS):
            if pkt[DNS].qd:
                pkt[DNS].qd.qname = 'www.example.com'
    
    wrpcap(DATASET_DIR+'/'+PREFIX+'04.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #5 change dns domain in dns query for specific address
    for pkt in pkts:
        if pkt.haslayer(DNS):
            if pkt[DNS].qd:
                if pkt[DNS].qd.qname == 'onecollector.cloudapp.aria.akadns.net':
                    pkt[DNS].qd.qname = 'example.com'
    
    wrpcap(DATASET_DIR+'/'+PREFIX+'05.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #6 change payload in http request
    for pkt in pkts:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 80:
                payload = pkt.lastlayer()
                payload.original = re.sub(r'\s\d|\S*\.com', 'example.com', str(payload.original))
    
    wrpcap(DATASET_DIR+'/'+PREFIX+'06.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #7 change payload in request and change ip address
    for pkt in pkts:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 443:
                payload = pkt.lastlayer()
                payload.original = re.sub(r'\s\d|\S*\.com', 'example.com', str(payload.original))
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.3.4.42':
                pkt[IP].src = '1.1.1.1'
        
    wrpcap(DATASET_DIR+'/'+PREFIX+'07.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #8 change tls message
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.3.4.42':
                if pkt.haslayer(TLS):
                    if pkt[TLS].type == 23:
                        pkt[TLS].msg = b'example.com'

    wrpcap(DATASET_DIR+'/'+PREFIX+'08.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #9 change source mac address only for source ip address 10.2.2.27
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.2.2.27':
                pkt.src = '00:00:00:00:00:01'
        
    wrpcap(DATASET_DIR+'/'+PREFIX+'09.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #10 change dest mac address only for dest ip address 4.122.55.7
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].dst == '4.122.55.7':
                pkt.dst = '00:00:00:00:00:02'
            
    wrpcap(DATASET_DIR+'/'+PREFIX+'10.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #11 change protocol to udp for source ip address 10.2.2.27
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.2.2.27':
                pkt[IP].proto = 17

    wrpcap(DATASET_DIR+'/'+PREFIX+'11.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #12 remove payload for source ip address 10.2.2.27
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.2.2.27':
                pkt.remove_payload()

    wrpcap(DATASET_DIR+'/'+PREFIX+'12.pcap', pkts)

    #13 change dns answer in dns response
    for pkt in pkts:
        if pkt.haslayer(DNS):
            if pkt[DNS].an:
                if pkt.haslayer(IP):
                    if pkt[IP].src == '4.122.55.3':
                        pkt[DNS].an = b'1.1.1.1'
            
    wrpcap(DATASET_DIR+'/'+PREFIX+'13.pcap', pkts)

    #14 change tls message type
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.3.4.42':
                if pkt.haslayer(TLS):
                    if pkt[TLS].type == 23:
                        pkt[TLS].type = 22

    wrpcap(DATASET_DIR+'/'+PREFIX+'14.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #15 change tls message len
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '10.3.4.42':
                if pkt.haslayer(TLS):
                    if pkt[TLS].type == 23:
                        pkt[TLS].len = 100

    wrpcap(DATASET_DIR+'/'+PREFIX+'15.pcap', pkts)
    pkts = copy.deepcopy(orig)


    
def make_dataset_multi(pkts):
    print('Creating multi dataset')

    orig = copy.deepcopy(pkts)

    #16 change source ip address, port, mac address
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].dst == '184.51.9.105':
                pkt[IP].src = '10.3.8.89'
                pkt.src = '00:00:00:00:00:01'
                pkt.dst = '00:00:00:00:00:02'

                if pkt.haslayer(TCP):
                    pkt[TCP].sport = 10223

    wrpcap(DATASET_DIR+'/'+PREFIX+'16.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #17 change protocol to udp
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].dst == '4.122.55.2':
                pkt[IP].src = '1.1.1.1'
                pkt[IP].proto = 17
        
    wrpcap(DATASET_DIR+'/'+PREFIX+'17.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #18 change protocol to icmp if it is dhcp, and change its source mac address and ip address
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].proto == 17 and pkt[IP].dport == 67:
                pkt[IP].proto = 1
                pkt.src = '00:00:00:00:00:01'
                pkt[IP].src = '1.1.1.1'
    
    wrpcap(DATASET_DIR+'/'+PREFIX+'18.pcap', pkts)

def make_dataset_scapy_ext(pkts):
    print('Creating scapy_ext dataset')

    orig = copy.deepcopy(pkts)
    
    #19 change IP address
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].src == '4.122.55.1' and pkt[IP].dst == '4.122.55.254':
                pkt[IP].src = '4.122.55.198'
                pkt[IP].dst = '4.122.55.199'
            if pkt[IP].src == '4.122.55.254' and pkt[IP].dst == '4.122.55.1':
                pkt[IP].src = '4.122.55.199'
                pkt[IP].dst = '4.122.55.198'
    
    wrpcap(DATASET_DIR+'/'+PREFIX+'19.pcap', pkts)
    pkts = copy.deepcopy(orig)

    #20 change IP address so that it comes before DNS answer
    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt[IP].dst == '157.55.134.142':
                pkt[IP].dst = '104.96.141.107'

    wrpcap(DATASET_DIR+'/'+PREFIX+'20.pcap', pkts)
    pkts = copy.deepcopy(orig)



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

    print("Creating datasets from input file")
    make_dataset_tcprewrite()
    orig = copy.deepcopy(pkts)
    make_dataset_scapy(pkts)
    pkts = copy.deepcopy(orig)
    make_dataset_multi(pkts)
    pkts = copy.deepcopy(orig)
    make_dataset_scapy_ext(pkts)

if __name__ == '__main__':
    adjust_paths()
    ensure_file()
    ensure_dir()
    load_layer('tls')
    run_all()

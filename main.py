##################################################
## Main file for running the detector
##################################################
## File: main.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import argparse 

from detector import Detector

def get_args():
    '''
    Get arguments from command line
    Args:

    Returns:
        args: Arguments from command line
    '''
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input_pcap", metavar="PCAP_FILE_PATH", help="Input PCAP file path", required=False, type=str)
    group.add_argument("-d", "--dataset_dir", metavar="DATASET_DIR", help="Dataset directory path", required=False, type=str)
    parser.add_argument("-l", "--log", choices=["debug", "info", "warning", "error", "critical"], help="Log level", required=False, default="INFO")
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    
    args = get_args()
    Detector(args).run()

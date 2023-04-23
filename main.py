#! /usr/bin/env python3
# -*- coding: utf-8 -*-

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
import yaml

from src.detector import Detector

def get_args():
    '''
    Get arguments from command line
    Args:

    Returns:
        args: Arguments from command line
    '''
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--config", metavar="CONFIG_FILE_PATH", help="Config file", required=True, type=str)
    group.add_argument("-i", "--input_pcap", metavar="PCAP_FILE_PATH", help="Input PCAP file path", required=False, type=str)
    group.add_argument("-d", "--dataset_dir", metavar="DATASET_DIR", help="Dataset directory path", required=False, type=str)
    parser.add_argument("-l", "--log", choices=["debug", "info", "warning", "error", "critical"], help="Log level", required=False, default="INFO")
    args = parser.parse_args()
    return args

def check_config(config):
    '''
    Check if config file is valid, and if it contains all required keys
    Args:
        config: Config file

    Returns:
        True if config is valid, False otherwise
    '''
    try:
        with open(config, "r") as file:
            config_dict = yaml.safe_load(file)

            required_keys = ['database', 'app', 'tests']
            for key in required_keys:
                if key not in config_dict:
                    return False
            
            if config_dict['database']['engine'] != 'sqlite' or not config_dict['database']['file']:
                return False
            
            if 'chunk_size' not in config_dict['app'] or type(config_dict['app']['chunk_size']) is not int or config_dict['app']['chunk_size'] < 1:
                return False
            
            tests = config_dict['tests']
            required_keys = ['pcap', 'misc', 'link_layer', 'internet_layer', 'transport_layer', 'application_layer']
            for key in required_keys:
                if key not in tests:
                    return False
                if not isinstance(tests[key], bool):
                    return False
            
        return True
    except yaml.YAMLError as exc:
        return False

if __name__ == '__main__':
    
    args = get_args()
    if not check_config(args.config):
        raise Exception("Invalid config file")
    Detector(args).run()

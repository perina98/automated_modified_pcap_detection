##################################################
## Main file for checking configuration file and arguments
##################################################
## File: config.py
## Author: Lukáš Perina
## Email: 527341@mail.muni.cz
## Programme: FI N-SWE Software Engineering
## Plan: FI OPS Deployment and operations of software systems
## Year: 2022/2023
##################################################

import os
import argparse 
import yaml

class Config():
    '''
    Class for checking configuration file and arguments
    '''
    def get_args(self):
        '''
        Get arguments from command line
        Args:

        Returns:
            args: Arguments from command line
        '''
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--config", metavar="CONFIG_FILE_PATH", help="Config file, default is config.yml", required=False, type=str, default="config.yml")
        parser.add_argument("-l", "--log", choices=["debug", "info", "warning", "error", "critical"], help="Log level", required=False, default="INFO")

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-i", "--input_pcap", metavar="PCAP_FILE_PATH", help="Input PCAP file path", required=False, type=str)
        group.add_argument("-d", "--dataset_dir", metavar="DATASET_DIR", help="Dataset directory path", required=False, type=str)
        args = parser.parse_args()
        return args

    def check_config(self, config):
        '''
        Check if config file is valid, and if it contains all required keys
        Args:
            config: Config file

        Returns:
            True if config is valid, False otherwise
        '''

        # check if file exists and can be opened for reading
        if not os.path.isfile(config):
            return False
        
        if not os.access(config, os.R_OK):
            return False

        try:
            with open(config, "r") as file:
                config_dict = yaml.safe_load(file)

                required_keys = ['database', 'app', 'tests']
                for key in required_keys:
                    if key not in config_dict:
                        return False
                    
                required_keys = ['engine', 'file']
                for key in required_keys:
                    if key not in config_dict['database']:
                        return False
                    
                required_keys = ['chunk_size', 'workers', 'custom_private_network', 'allowed_communication_silence', 'check_last_bytes', 'allowed_latency_inconsistency']
                for key in required_keys:
                    if key not in config_dict['app']:
                        return False
                
                tests = config_dict['tests']
                required_keys = ['pcap', 'misc', 'link_layer', 'internet_layer', 'transport_layer', 'application_layer']
                for key in required_keys:
                    if key not in config_dict['tests']:
                        return False
                    if not isinstance(tests[key], bool):
                        return False

                
                if (type(config_dict['app']['workers']) is not int and config_dict['app']['workers'] is not None):
                    return False
                
                if type(config_dict['app']['workers']) is int:
                    if config_dict['app']['workers'] < 2:
                        return False
                
                if type(config_dict['app']['custom_private_network']) is not str and config_dict['app']['custom_private_network'] is not None:
                    return False
                
                if type(config_dict['app']['allowed_latency_inconsistency']) is not int and type(config_dict['app']['allowed_latency_inconsistency']) is not float:
                    return False
                
                for key in ['chunk_size', 'allowed_communication_silence', 'check_last_bytes']:
                    if type(config_dict['app'][key]) is not int or config_dict['app'][key] < 1:
                        return False
                
            return True
        except (yaml.YAMLError, TypeError, KeyError, UnicodeDecodeError) as exc:
            return False
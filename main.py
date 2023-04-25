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

from src.config import Config
from src.detector import Detector

if __name__ == '__main__':
    config = Config()
    args = config.get_args()
    if not config.check_config(args.config):
        print('Config file is not valid')
        exit(1)
    
    # all good, run the detector
    Detector(args).run()

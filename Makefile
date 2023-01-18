#!/bin/bash
export python:=python3

.PHONY: all dataset detector single

all : 
	@$(MAKE) -s clean
	@$(MAKE) -s dataset
	@$(MAKE) -s detector

dataset : clean
	python3 makedataset.py
detector :
	python main.py --dataset dataset
single :
	python main.py --input_pcap dataset/out-19.pcap -l debug
clean :
	rm -rf dataset

#!/bin/bash
export python:=python3

.PHONY: all dataset detector single

all : 
	@$(MAKE) -s clean
	@$(MAKE) -s dataset
	@$(MAKE) -s detector

dataset : clean
ifeq ($(OS),Windows_NT)
	mkdir dataset
else
	mkdir -p dataset
endif
	python3 makedataset.py
detector :
	python main.py --dataset dataset
single :
	python main.py --input_pcap dataset/out-19.pcap -l debug
clean :
ifeq ($(OS),Windows_NT)
	@if exist dataset rmdir /s /q dataset
else
	rm -rf dataset
endif

PYTHON := python

.PHONY: all dataset run_dataset single

all : 
	@$(MAKE) -s dataset
	@$(MAKE) -s run_dataset

dataset : clean
ifeq ($(OS),Windows_NT)
	mkdir dataset
else
	mkdir -p dataset
endif
	$(PYTHON) makedataset.py
run_dataset :
	$(PYTHON) main.py --dataset dataset -l debug
single :
	$(PYTHON) main.py --input_pcap input.pcap -l debug
clean :
ifeq ($(OS),Windows_NT)
	@if exist dataset rmdir /s /q dataset
else
	rm -rf dataset
endif
install :
	pip install -r requirements.txt
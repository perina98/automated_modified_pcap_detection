PYTHON := python

.PHONY: all dataset run_dataset single

all : 
	@$(MAKE) -s dataset
	@$(MAKE) -s run_dataset

dataset : clean
	mkdir dataset
	mkdir -p dataset
	$(PYTHON) makedataset.py
run_dataset :
	$(PYTHON) main.py -c config.yml --dataset dataset -l debug
single :
	$(PYTHON) main.py -c config.yml --input_pcap ignore/home.pcap -l debug
clean :
ifeq ($(OS),Windows_NT)
	@if exist dataset rmdir /s /q dataset
else
	rm -rf dataset
endif
install :
	pip install -r requirements.txt
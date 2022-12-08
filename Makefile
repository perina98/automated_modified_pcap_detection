.PHONY: all dataset detector single

all : 
	@$(MAKE) -s clean
	@$(MAKE) -s dataset
	@$(MAKE) -s detector

dataset : clean
	python3 makedataset.py
detector :
	python3 detector.py --dataset dataset
single :
	python3 detector.py --input_pcap dataset/out-19.pcap
clean :
	rm -rf dataset

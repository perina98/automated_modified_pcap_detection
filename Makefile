all : 
	@$(MAKE) -s clean
	@$(MAKE) -s dataset
	@$(MAKE) -s detector

dataset :
	python3 makedataset.py
detector :
	python3 detector.py
clean :
	rm -rf dataset
PYTHON := python
ZIPNAME := 527341

.PHONY: all dataset run_dataset single clean install zip

all : 
	@$(MAKE) -s dataset
	@$(MAKE) -s run_dataset

dataset :
	$(PYTHON) src/createdataset.py
run_dataset :
	$(PYTHON) main.py --dataset dataset -o -l debug
single :
	$(PYTHON) main.py --input_pcap static/input.pcap -o -l debug
clean :
	rm -rf dataset
	rm -rf *.db
	rm -rf *.html
	rm -rf *.zip
	find . -name '__pycache__' -exec rm -r {} +
install :
	pip install -r requirements.txt
pack: clean
	zip -r $(ZIPNAME).zip . --exclude=".git/*" --exclude="ignore/*" --exclude="./TODO"
# Detector 

Detector is a python script with custom modules designed to detect changes made to pcap files for forensic analysis and identification of malicious activities.

This script offers a range of modules that can be seletively enabled or disabled. These modules have been developed to detect various types of suspicious activity such as packet modification, injection and more. 

One of the key features is the ability to generate a score that represents the probability that a given pcap file has been altered. Score is based on analysis and each function is given an impact score that is later calculated to give overal probability of pcap manipulation.

## Installation

Requirements for this scipts are the following:

```
capinfos
python 3.8 or higher
sqlalchemy v2.0.9
scapy v2.5.0
pyyaml v6.0
```

In order to generate dataset you will also need the following:

```
tcprewrite
```

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install requirements like sqlalchemy and scapy.

```bash
pip install sqlalchemy
pip install scapy
pip install pyyaml
```

Alternatively, you can just run this command that will install the requirements.
```bash
make install
```

## Usage

Before running the app, check config.yml file and set your preferences there.
It is possible to set different name for database file, packet save chunk size and which tests to run.

```bash
python main.py --config config.yml --input_pcap input.pcap
```

## Options

```
-c, --config           Config file, required option
-i, --input_pcap       Input PCAP file path
-d, --dataset_dir      Dataset directory path
-l, --log              Log level
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
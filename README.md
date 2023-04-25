# Detector 

Detector is a python script with custom modules designed to detect changes made to pcap files and packets themselves for forensic analysis and identification of malicious activities.

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

## Generating dataset

In order to generate dataset, you need to run
```bash
python src/createdataset.py
```

or just 

```bash
make dataset
```

which will generate dataset files in /dataset folder which will be created if it does not exist yet.
Default file used for creating the dataset is static/input.pcap. You can edit this in the src/createdataset.py script.

After each file is created, information about this file and its modifications are printed on STDOUT.

## Config file

Config file is crucial for running the application. If no -c or --config options are specified, config.yml is used. If file does not exists, program ends.

Config consists of 3 main root keys:

database, app, tests

database contains 2 subkeys
```
engine - database engine, only sqlite was tested
file   - filename for database that will be created in the current folder
```

app consists of 6 subkeys
```
chunk_size                      - (int) number of packets to be processed in one chunk (required)
check_last_bytes                - (int) check last x bytes of the file (required)
allowed_communication_silence   - (int) communication silence in seconds (required)
allowed_latency_inconsistency   - (int / float) latency should not be more than x times different (required)
workers                         - (int / null) number of workers, leave it empty to use all available cores
custom_private_network          - (ipv4/ipv6 network / null) if you want to add your own private network (e.g. 10.0.0.0/8), leave it empty otherwise
```

tests consist of 6 subkeys representing each test module
```
pcap                - (bool) Turns on or off pcap tests
misc                - (bool) Turns on or off misc tests
link_layer          - (bool) Turns on or off link_layer tests
internet_layer      - (bool) Turns on or off internet_layer tests
transport_layer     - (bool) Turns on or off transport_layer tests
application_layer   - (bool) Turns on or off application_layer tests
```

## Usage

Before running the app, check config.yml file and set your preferences there.
It is possible to set different name for database file, packet save chunk size and which tests to run.

```bash
python main.py --input_pcap static/input.pcap
```

## Example output

TODO

## Options

```
-c, --config           Config file, default is config.yml
-i, --input_pcap       Input PCAP file path
-d, --dataset_dir      Dataset directory path
-l, --log              Log level
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
# Detector 

Detector is a python script with custom modules designed to detect changes made to pcap files and packets themselves for forensic analysis and identification of malicious activities. Application also provides support for pcapng files.

This script offers a range of modules that can be seletively enabled or disabled. These modules have been developed to detect various types of suspicious activity such as packet modification, injection and more. Different detection methods can be turned on or off in config.yml file. In the config.yml file it is also possible to tweak application parameters.

One of the key features is the ability to generate a score that represents the probability that a given pcap file has been altered. Score is based on analysis and each function is given an impact score that is later calculated to give overal probability of pcap manipulation.

## Installation

Requirements for this scipts are the following:

```
capinfos (Included in Wireshark)
python 3.8 or higher with pip
sqlalchemy v2.0.9
scapy v2.5.0
pyyaml v6.0
```

In order to generate dataset you will also need the following:

```
tcprewrite (Part of tcpreplay)
```

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install requirements like sqlalchemy and scapy.
These requirements are also stored in a requirements.txt file for easier installation.

```bash
pip install sqlalchemy
pip install scapy
pip install pyyaml
```

Alternatively, you can just run this command that will install the requirements.
```bash
make install
```
or run
```bash
pip install -r requirements.txt
```
directly.

## Generating dataset

In order to generate dataset, you need to run
```bash
python src/createdataset.py
```

or just 

```bash
make dataset
```

You will also need the following:
```
tcprewrite
Around 225MB of free disk space.
```

which will generate 30 dataset files in ./dataset folder which will be created if it does not exist yet.
Default file used for creating the dataset is static/input.pcap. You can edit this in the src/createdataset.py script.
The static/input.pcap example pcap file is based on [this research](https://www.sciencedirect.com/science/article/pii/S2352340920306788)

Information about each dataset file is printed on STDOUT before the file is created.

## Config file

Config file is crucial for running the application. If no `-c` or `--config` options are specified, config.yml is used. If file does not exist, program ends.

Config consists of 3 main root keys:
database, app, tests

database contains 2 subkeys
```
engine - database engine, only sqlite was tested
file   - filename for database that will be created in the current folder
```

app consists of 8 subkeys
```
chunk_size                      - (int) number of packets to be processed in one chunk, minimum is 1 (required)
buffer_multiplier               - (int) multiplier for the buffer size, memory and speed related, minimum is 2 (required)
ntp_timestamp_threshold         - (int / float) threshold difference between NTP timestamp and packet timestamp (required)
check_last_bytes                - (int) check last x bytes of the file (required)
allowed_communication_silence   - (int) communication silence in seconds (required)
allowed_latency_inconsistency   - (int / float) latency should not be more than x times different (required)
workers                         - (int / none) number of workers, leave it empty to use all available cores, minimum is 2
custom_private_network          - (ipv4/ipv6 network / none) if you want to add your own private network (e.g. 18.0.0.0/8), leave it empty otherwise
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

```
Processing pcap: static/input.pcap
Processed 12000 / 12000 packets. Est. time remaining: 0.00 seconds
Finished processing packets

=== Results === static/input.pcap

Pcap modifications:
Snaplen context mismatch  =  Not modified
File and data size mismatch  =  Not modified

Packet modifications:
Mismatched checksums  =  0/12000
Mismatched protocols  =  1954/12000
Incorrect packet length  =  0/12000
Invalid packet payload  =  2/12000
Insuficient capture length  =  0/12000
Mismatched NTP timestamp  =  0/12000
Missing ARP traffic  =  5/18
Inconsistent MAC maps  =  10/199
Lost ARP traffic  =  3/16
Missing ARP responses  =  6/16
Inconsistent TTLs  =  8/238
Inconsistent fragmentation  =  0/11716
Sudden drops for IP source  =  15/173
Inconsistent interpacket gaps  =  1/139
Incomplete tcp streams  =  73/139
Inconsistent MSS  =  0/238
Inconsistent window size  =  4/238
Mismatched ciphers  =  0/139
Mismatched DNS query answer  =  0/157
Mismatched DNS answer stack  =  0/157
Missing translation of visited domain  =  7426/12000
Translation of unvisited domains  =  16/157
Incomplete FTP  =  0/0
Missing DHCP IPs  =  0/1
Missing ICMP IPs  =  0/3
Inconsistent user agent  =  1/23

Probability of modification: 29.93%
Total time: 29.51 seconds
```

## Options

```
-c, --config           (string) Config file, default is config.yml
-i, --input_pcap       (string) Input PCAP file path
-d, --dataset_dir      (string) Dataset directory path
-l, --log              (string) Log level
-o, --outputhtml       Output results to html file
-f, --filelog          Log application tasks and result to log.log file
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
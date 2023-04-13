# Detector 

Detector is a python script with custom modules used to detect changes made to the pcap file.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install requirements like sqlalchemy and scapy.

```bash
pip install sqlalchemy
pip install scapy
```

Alternatively, you can just run this command that will install the requirements.
```bash
make install
```

## Usage

```bash
python main.py --input_pcap input.pcap
```

## Options

```
-i, --input_pcap       Input PCAP file path
-d, --dataset_dir      Dataset directory path
-l, --log              Log level
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
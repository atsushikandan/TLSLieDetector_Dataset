# TLSLieDetector_Dataset
Dataset for TLS Lie Detector

# The dataset used in our research
The dataset used in the original experiment is in [dataset.zip](https://github.com/atsushikandan/TLSLieDetector_Dataset/releases/download/v1.0.0/dataset.zip).

It contains the following data.

```
dataset
├── hextext : hexadecimal strings of encrypted data [txt]
├── pcap : pcaps of benign (normal) data [pcap]
└── source_plaintext : original data (Windows OS command output) [txt]
```

# How to re-create the dataset

1. Build the docker images for the experiment.

```sh
$ cd docker
$ bash build-all.sh
```

2. Create the dataset.

```sh
$ cd ../dataset_creation
$ bash run-all.sh
```

All data created is in the `dataset` directory.

```
dataset
├── feature : extracted features [csv]
├── hextext : hexadecimal strings of encrypted data [txt]
├── pcap : pcaps of benign (normal) data [pcap]
└── source_plaintext : original data (Windows OS command output) [txt]
```

# Author
- Atsushi Kanda
- Masaki Hashimoto
- Takao Okubo


# LICENSE
This repository contains codes originally developed by The Mbed TLS Contributors under the Apache License, Version 2.0.

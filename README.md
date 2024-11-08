# LLM-Fuzz

LLM-Fuzz：A novel Fuzzer utilizing Large Language Model for Ethereum Smart Contract Vulnerability Detection.

## Download

```
git config --global http.sslBackend gnutls
git clone https://github.com/honghaojia/LLM-Fuzz.git
```

## Requirements

LLM-Fuzz is running on Linux(ideally Ubuntu 22.04)

Dependencies:

- CMake:>=3.5.1
- python:>=3.10
- leveldb:1.23
- solc:0.4.26
- curl:8.5.0

### Install Dependencies on Linux

- leveldb:

```
sudo apt-get update
sudo apt-get install -y libleveldb-dev
```

- solc 0.4.26:

Our dataset use smart contracts whose solidity versions are below 0.4.26 ,so our LLM-Fuzz use  solc compiler 0.4.26. if you need more dertails,please check https://github.com/crytic/solc-select

```
pip3 install solc-select
solc-select install 0.4.26
solc-select use 0.4.26
```

- curl:

```
sudo apt update
sudo apt install curl
```

## Architecture

```
$(LLM-Fuzz)
├── sFuzz
│   ├── fuzzer
│   ├── libfuzzer
│   └── ...
├── assets
│   ├── ReentrancyAttacker_model.sol
│   ├── ReentrancyAttacker.sol
│   └── ...
├── source
│   └── ...
├── rename_contracts
│   └── ...
├── contracts
│   └── ...
├── tools
│   ├── contracts_edit.cpp
│   └── rename.py
├── initial_.sh
├── run.sh
└── README.md
```

- `sFuzz`:The basic fuzzing module of LLM-Fuzz
- `assets`:
  - `ReentrancyAttacker_model.sol`: The template for constructing an attacker contract
  - `ReentrancyAttacker.sol`: The attacker contract generated based on the template
- `source`:The source code of smart contracts
- `rename_contracts`:Store contracts that are renamed by their actual contracts name
- `contracts`:target mart contracts
- `tools`:Essential tools to make the fuzzer work

## Prepare

Before officially using LLM-Fuzz, you must replace the API KEY in your code with your API key.There are two places where the API KEY needs to be replaced,one is to add contract events, and the other is in the sFuzz module.

- first place you need to replace your LLM API with is when adding events into contract,it determins what LLM you use when add events to contract.

first file path:

```
$(LLM-Fuzz)
├── tools
│   ├── contracts_edit.cpp <--here
│   └── rename.py
```

- second place you need to replace your LLM API with is within sFuzz module,it determins what LLM you use when fuzzing.

second file path:

```
$(LLM-Fuzz)
├── sFuzz
│   ├── fuzzer
│   ├── libfuzzer
│   	├── LLMhelper <--here
│   	├── ContractABI
│   	└── ...
```

### note

You may face failure to add events. If you encounter this situation, please try a few more times or change another larger language model.

More information please visit ChatGPT API reference:[API Reference - OpenAI API](https://platform.openai.com/docs/api-reference/introduction)and Claude API reference:[入门 - Claude API](https://claude.apifox.cn/doc-3090880).

## Quick Start

In this part ,we will show you how to run LLM-Fuzz.

```
cd LLM-Fuzz
```

- add events to contracts

```
./edit_source.sh
```

- create fuzzer file 

```
./initial.sh
```

- run LLM-Fuzz

```
./run.sh
```

### note

- You have to replace your LLM API Key before run LLM-Fuzz. 

- If you have any questions ,please email to honghaojia@cug.edu.com

## Dataset
We release our dataset used in our examination at page https://github.com/honghaojia/Dataset ,which has added events using ChatGPT-4,it contains 695 smart contracts in total.





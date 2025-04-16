# ICEPRE
## Introduction
A novel data-driven protocol reverse engineering (PRE) tool based on concolic execution that uniquely integrates network trace with static analysis.
It supports both single message inference and batch processing of multiple messages from a PCAP file.

[//]: # (## Features)

[//]: # (* Supports concolic execution and tracing of binary programs)


## Dependencies
* angr
* scikit-learn
* memory-profiler
* archinfo
* claripy
* pandas
* scapy
* Netzob
* ipython
* tracer
* pyvex
* thefuzz
* cle
* capstone

## Installation
To install ConcolicTrace, simply run:

`pip install -r requirements.txt`.

## Directory Structure
```aiignore
ICEPRE
├── config/
│   ├── enip_config.yaml
│   ├── iec104_config.yaml
│   ├── modbus_config.yaml
│   └── s7comm_config.yaml
├── firmware/
├── traffic/
├── evaluation/
│   ├── nemesysUtils
│   └── syntax_evaluation.py
├── ICEPRE.py
├── Ctracer.py
├── CtraceSimProcedures.py
├── InferSyntax.py
├── results/
│   ├── Ctracer_log.txt
│   └── {Protocol}_{messages_num}_messages.csv
└── tracer-modified.py
```

## Usage

### Command-Line Arguments

The script accepts the following arguments:

| Argument               | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `-p`, `--protocol`     | **Required**. Name of the protocol to infer (e.g., `modbus`, `s7comm`).     |
| `-c`, `--config`       | **Required**. Path to the YAML configuration file.                          |
| `-b`, `--batch`        | Enable batch mode for processing multiple messages from a PCAP file.        |
| `-f`, `--pcap_file`    | **Required in batch mode**. Path to the PCAP file containing messages.      |
| `-n`, `--num_messages` | **Required in batch mode**. Number of messages to process from the PCAP.    |
| `-d`, `--hex_data`     | **Required in non-batch mode**. Hexadecimal string of the message to infer. |

### Configuration File (YAML)

The configuration file should include the following keys:

```yaml
binary_p: /path/to/binary
library_dir: /path/to/library
hook_option:
  hook_s: "function_name"  # Name of the input reception function (optional)
  hook_addr: 0x123456    # Address of the input reception function
  end_s: "symbol_name"   # Terminate analysis when this function is encountered (optional)
  end_addr: 0x654321     # The last basic block address of the protocol parsing function
```

### Examples

#### Single Message Inference

To infer the field boundary of a single message:

```bash
python ICEPRE.py -p modbus -c config/modbus_config.yaml -d "000200000006ff0101300001"
```

- `-p modbus`: Specifies the protocol as `modbus`.
- `-c config.yaml`: Path to the configuration file.
- `-d "000200000006ff0101300001"`: Hexadecimal string of the message to infer.

#### Batch Mode (PCAP File)

To process multiple messages from a PCAP file:

```bash
python ICEPRE.py -p modbus -c config/modbus_config.yaml -b -f traffic.pcap -n 10
```

- `-b`: Enables batch mode.
- `-f traffic.pcap`: Path to the PCAP file.
- `-n 10`: Number of messages to process from the PCAP file.

### Output

- In **single message mode**, the script prints the inferred field boundary to the console.
- In **batch mode**, the results are saved to a CSV file in the `results/` directory. The file name follows the format:  
  ```
  results/<protocol>_<num_messages>_messages.csv
  ```

The CSV file contains the following columns:
- `No.`: Message number.
- `Raw Data`: Hexadecimal representation of the message.
- `Ground Truth`: Ground truth of the message structure.
- `Inference Result`: Inferred message structure.

Additionally, the file includes evaluation metrics:
- `Accuracy`, `Precision`, `Recall`, `F1 Score`, and `Perfection`.


# SNMP-DoS
SNMP GETBULK DoS

# SNMP Reflection and Amplification Vulnerability Checker

This tool checks whether a target host is vulnerable to SNMP reflection and amplification attacks. By sending a SNMP GETBULK request to the target, the tool calculates the amplification factor to determine if the host is susceptible to these types of attacks.

## Features

- **SNMP Version**: SNMPv2c (default)
- **Amplification Check**: Calculates the amplification factor based on the request and response sizes.
- **Community String**: Supports custom SNMP community strings.

## Requirements

- Python 3.x
- pysnmp library

## Installation

To get started, clone the repository and install the required dependencies.

```bash
# Clone the repository
git clone https://github.com/omemishra/SNMP-DoS.git

# Navigate to the project directory
cd SNMP-DoS

# Install the required Python packages
pip install pysnmp
```
## Usage

To use the tool, run the script with the target IP address. You can optionally specify a different SNMP community string (default is `public`).

### Basic Example

```bash
python3 SNMPDoS.py 1.1.1.1
```

### Custom Community String

```bash
python3 SNMPDoS.py 1.1.1.1 --community myCommunityString
```

### Output

- The script will display the request size, response size, and amplification factor.
- If the amplification factor is greater than 1, the target is considered vulnerable to SNMP reflection/amplification.

## Example Output

```text
Request size: 15 bytes
Response size: 1024 bytes
Amplification Factor: 68.27
[!] 1.1.1.1 is vulnerable to SNMP reflection/amplification
```

## Notes

- Ensure that the target IP address is reachable and the SNMP service is running.
- The script uses SNMPv2c by default, which is more common in network devices.


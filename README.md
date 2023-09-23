# NetSNMP Inventory Tool
## What is this?
An inventory tool for network equipment discovery & audit, based on ICMP PING (device detection) + SNMP (data obtaining) protocols.

## How it works?
1. The tool scans each address in the given network with an ICMP PING.
2. If an address responds to PING, the tool trying to obtain information from general OIDs (corresponding to [RFC3418](https://www.rfc-editor.org/rfc/rfc3418.html)) using GET and GET-NEXT SNMP requests.
3. If specific vendor was detected, the tool will use additional vendor's "private" OIDs in SNMP requests for additional information gathering or it's clarification.
4. When all information fetched, the tool will generate the report in CSV format.

## What information is gathering?
| Parameter                 | Object           | Node                   | OID                                                                       |
| ----------------------- | --------------- | --------------------- | -------------------------                                               |
| System name               | Sysname          | sysName                | [1.3.6.1.2.1.1.5](https://oidref.com/1.3.6.1.2.1.1.5)                     |
| System manufacturer       | Manufacturer     | entPhysicalMfgName     | [1.3.6.1.2.1.47.1.1.1.1.12](https://oidref.com/1.3.6.1.2.1.47.1.1.1.1.12) |
| System model              | Model            | entPhysicalModelName   | [1.3.6.1.2.1.47.1.1.1.1.13](https://oidref.com/1.3.6.1.2.1.47.1.1.1.1.13) |
| System software version   | FW               | entPhysicalSoftwareRev | [1.3.6.1.2.1.47.1.1.1.1.10](https://oidref.com/1.3.6.1.2.1.47.1.1.1.1.10) |
| System serial number      | S/N              | entPhysicalSerialNum   | [1.3.6.1.2.1.47.1.1.1.1.11](https://oidref.com/1.3.6.1.2.1.47.1.1.1.1.11) |
| System location           | Location         | sysLocation            | [1.3.6.1.2.1.1.6](https://oidref.com/1.3.6.1.2.1.1.6)                     |
| System description        | Description      | sysDescr               | [1.3.6.1.2.1.1.1](https://oidref.com/1.3.6.1.2.1.1.1)                     |
| Responsible contact       | Contact          | sysContact             | [1.3.6.1.2.1.1.4](https://oidref.com/1.3.6.1.2.1.1.4)                     |
| Entity description        | Comment          | entLogicalDescr        | [1.3.6.1.2.1.47.1.2.1.1.2](https://oidref.com/1.3.6.1.2.1.47.1.2.1.1.2)   |
| System interfaces count   | Interfaces Count | ifNumber               | [1.3.6.1.2.1.2.1](https://oidref.com/1.3.6.1.2.1.2.1)                     |
| Primary MAC address       | MAC Address      | ifPhyAddress           | [1.3.6.1.2.1.2.2.1.6](https://oidref.com/1.3.6.1.2.1.2.2.1.6)             |
| System IP addresses       | IP Addresses     | ipAdEntAddr            | [1.3.6.1.2.1.4.20.1.1](https://oidref.com/1.3.6.1.2.1.4.20.1.1)           |
| Response to ICMP PING     | PING             | N/A                    | N/A                                                                       |
| Response to SNMP requests | SNMP             | N/A                    | N/A                                                                       |

## What specific vendors are supported?
For now, only additional OIDs for Fortinet's FortiGate devices are present.

## What are system requirements?
- Python 3.10 or newer.
- Additional libraries.

## Are there any limitations?
Yes. For now this tool works only with SNMPv3.

## How to install?
1. Get the code: `git clone https://github.com/STwilight/net-snmp-inventory.git`.
2. Go into directory: `cd net-snmp-inventory-main`.
3. Install dependencies: `pip install -r requirements.txt`.
4. Copy to LLDP module to Python's PySNMP MIBs folder: `cp .\pysnmp_mibs\LLDP-MIB.py <PYTHON DIR>\Lib\site-packages\pysnmp_mibs\`.

## How to use?
1. Read the help: `python .\net-snmp-inventory.py --help`.
2. Run the scan: `python .\net-snmp-inventory.py --net 192.0.2.0/24 --sec_name "snmp-user" --auth_proto sha1 --auth_passwd "authentication-pass" --priv_proto aes128 --priv_passwd "priviledged-pass"`.
3. Monitor progress in the console.
4. Get the report in working dir.
5. Enjoy :)

## What's the plans?
- Process additional specific attributes for other hardware vendors.
- Implement support of SNMP v1 and v2 protocol.
- Create standalone executable file.

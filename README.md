# NetSNMP Inventory Tool
## What is this?
An inventory tool for network equipment discovery & audit, based on ICMP PING (device detection) + SNMP (data obtaining) protocols.

## How it works?
1. The tool scans each address in the given network with an ICMP PING.
2. If an address responds to PING, the tool trying to obtain information about device itself, network interfaces, originating networks, and neighbor devices (via LLDP) from OIDs (corresponding to [RFC3418](https://www.rfc-editor.org/rfc/rfc3418.html) and extensions) using GET and GET-NEXT SNMP requests.
3. If specific vendor was detected, the tool will use additional vendor's "private" OIDs in SNMP requests for an extra information gathering or it's clarification.
4. When all information fetched, the tool will generate the reports in CSV format.

## What information is gathering?
### Inventory data about device itself
| Parameter                 | Object           | Node                   | OID                                                                       |
| ----------------------- | --------------- | --------------------- | -------------------------------------------------------------------- |
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
| Primary MAC address       | MAC Address      | ifPhysAddress          | [1.3.6.1.2.1.2.2.1.6](https://oidref.com/1.3.6.1.2.1.2.2.1.6)             |
| System IP addresses       | IP Addresses     | ipAdEntAddr            | [1.3.6.1.2.1.4.20.1.1](https://oidref.com/1.3.6.1.2.1.4.20.1.1)           |
| Response to ICMP PING     | PING             | N/A                    | N/A                                                                       |
| Response to SNMP requests | SNMP             | N/A                    | N/A                                                                       |

### Data from vendor-specific OIDs
| Parameter               | Object | Node         | OID                                                                           |
| --------------------- | ------ | ----------- | ------------------------------------------------------------------------ |
| System software version | FW     | fgSysVersion | [1.3.6.1.4.1.12356.101.4.1.1](https://oidref.com/1.3.6.1.4.1.12356.101.4.1.1) |
| System serial number    | S/N    | fnSysSerial  | [1.3.6.1.4.1.12356.100.1.1.1](https://oidref.com/1.3.6.1.4.1.12356.100.1.1.1) |

### Data about network interfaces (including IP addresses and networks / connected routes)
| Parameter                       | Object           | Node                                          | OID                                                                                                                                                                                                    |
| ----------------------------- | --------------- | ---------------------------------------    | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Interface index                 | Index            | ifIndex,<br>ipAdEntIfIndex,<br>ipRouteIfIndex | [1.3.6.1.2.1.2.2.1.1](https://oidref.com/1.3.6.1.2.1.2.2.1.1),<br>[1.3.6.1.2.1.4.20.1.2](https://oidref.com/1.3.6.1.2.1.4.20.1.2),<br>[1.3.6.1.2.1.4.21.1.2](https://oidref.com/1.3.6.1.2.1.4.21.1.2) |
| Interface name                  | Name             | ifName                                        | [1.3.6.1.2.1.31.1.1.1.1](https://oidref.com/1.3.6.1.2.1.31.1.1.1.1)                                                                                                                                    |
| Interface alias                 | Alias            | ifAlias                                       | [1.3.6.1.2.1.31.1.1.1.18](https://oidref.com/1.3.6.1.2.1.31.1.1.1.18)                                                                                                                                  |
| Interface description           | Description      | ifDescr                                       | [1.3.6.1.2.1.2.2.1.2](https://oidref.com/1.3.6.1.2.1.2.2.1.2)                                                                                                                                          |
| Interface type                  | Type             | ifType                                        | [1.3.6.1.2.1.2.2.1.3](https://oidref.com/1.3.6.1.2.1.2.2.1.3)                                                                                                                                          |
| Interface MTU                   | MTU              | ifMtu                                         | [1.3.6.1.2.1.2.2.1.4](https://oidref.com/1.3.6.1.2.1.2.2.1.4)                                                                                                                                          |
| Interface MAC address           | MAC Address      | ifPhysAddress                                 | [1.3.6.1.2.1.2.2.1.6](https://oidref.com/1.3.6.1.2.1.2.2.1.6)                                                                                                                                          |
| Interface IP address            | IP Address       | ipAdEntAddr                                   | [1.3.6.1.2.1.4.20.1.1](https://oidref.com/1.3.6.1.2.1.4.20.1.1)                                                                                                                                        |
| Interface network mask          | Netmask          | ipAdEntNetMask                                | [1.3.6.1.2.1.4.20.1.3](https://oidref.com/1.3.6.1.2.1.4.20.1.3)                                                                                                                                        |
| Interface network mask (CIDR)   | CIDR             | N/A                                           | N/A                                                                                                                                                                                                    |
| Route type                      | N/A              | ipRouteType                                   | [1.3.6.1.2.1.4.21.1.8](https://oidref.com/1.3.6.1.2.1.4.21.1.8)                                                                                                                                        |
| Route destination               | Route Network    | ipRouteDest                                   | [1.3.6.1.2.1.4.21.1.1](https://oidref.com/1.3.6.1.2.1.4.21.1.1)                                                                                                                                        |
| Route network mask              | Route Mask       | ipRouteMask                                   | [1.3.6.1.2.1.4.21.1.11](https://oidref.com/1.3.6.1.2.1.4.21.1.11)                                                                                                                                      |
| Route network mask (CIDR)       | Route CIDR       | N/A                                           | N/A                                                                                                                                                                                                    |
| Route next hop                  | Next Hop         | ipRouteNextHop                                | [1.3.6.1.2.1.4.21.1.7](https://oidref.com/1.3.6.1.2.1.4.21.1.7)                                                                                                                                        |
| Interface administrative status | Admin Status     | ifAdminStatus                                 | [1.3.6.1.2.1.2.2.1.7](https://oidref.com/1.3.6.1.2.1.2.2.1.7)                                                                                                                                          |
| Interface operational status    | Operation Status | ifOperStatus                                  | [1.3.6.1.2.1.2.2.1.8](https://oidref.com/1.3.6.1.2.1.2.2.1.8)                                                                                                                                          |

### Data about device's neighbors (via LLDP)
| Parameter                        | Object                  | Node                                                                    | OID                                                                                                                                                                                                                             |
| ------------------------------ | --------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local system interface index     | Local Int. Index        | lldpRemLocalPortNum,<br>lldpRemSysName (OID),<br>lldpRemChassisId (OID) | [1.0.8802.1.1.2.1.4.1.1.2](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.2),<br>[1.0.8802.1.1.2.1.4.1.1.9](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.9),<br>[1.0.8802.1.1.2.1.4.1.1.5](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.5) |
| Local system interface name      | Local Int. Name         | ifName                                                                  | [1.3.6.1.2.1.31.1.1.1.1](https://oidref.com/1.3.6.1.2.1.31.1.1.1.1)                                                                                                                                                             |
| Neighbor's system name           | Remote Sysname          | lldpRemSysName                                                          | [1.0.8802.1.1.2.1.4.1.1.9](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.9)                                                                                                                                                         |
| Neighbor's system vendor's name  | Remote Vendor           | N/A                                                                     | N/A                                                                                                                                                                                                                             |
| Neighbor's system description    | Remote Description      | lldpRemSysDesc                                                          | [1.0.8802.1.1.2.1.4.1.1.10](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.10)                                                                                                                                                       |
| Neighbor's system capabilities   | Remote Capabilities     | lldpRemSysCapEnabled                                                    | [1.0.8802.1.1.2.1.4.1.1.12](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.12)                                                                                                                                                       |
| Neighbor's interface index       | Remote Int. Index       | lldpRemIndex                                                            | [1.0.8802.1.1.2.1.4.1.1.3](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.3)                                                                                                                                                         |
| Neighbor's interface ID type     | Remote Int. ID Type     | lldpRemPortIdSubtype                                                    | [1.0.8802.1.1.2.1.4.1.1.6](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.6)                                                                                                                                                         |
| Neighbor's interface ID          | Remote Int. ID          | lldpRemPortId                                                           | [1.0.8802.1.1.2.1.4.1.1.7](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.7)                                                                                                                                                         |
| Neighbor's interface description | Remote Int. Description | lldpRemPortDesc                                                         | [1.0.8802.1.1.2.1.4.1.1.8](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.8)                                                                                                                                                         |
| Neighbor's chassis ID type       | Remote Chassis ID Type  | lldpRemChassisIdSubtype                                                 | [1.0.8802.1.1.2.1.4.1.1.4](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.4)                                                                                                                                                         |
| Neighbor's chassis ID            | Remote Chassis ID       | lldpRemChassisId                                                        | [1.0.8802.1.1.2.1.4.1.1.5](https://oidref.com/1.0.8802.1.1.2.1.4.1.1.5)                                                                                                                                                         |
| Neighbor's interface index type  | N/A                     | lldpRemManAddrIfSubtype                                                 | [1.0.8802.1.1.2.1.4.2.1.3](https://oidref.com/1.0.8802.1.1.2.1.4.2.1.3)                                                                                                                                                         |
| Neighbor's interface IP address  | Remote Int. IP Address  | lldpRemManAddrIfId (OID)                                                | [1.0.8802.1.1.2.1.4.2.1.4](https://oidref.com/1.0.8802.1.1.2.1.4.2.1.4)                                                                                                                                                         |

## What specific vendors are supported?
For now, only additional OIDs for Fortinet's FortiGate devices are present.

## What are system requirements?
- Python 3.10 or newer.
- Additional libraries and modules.

## Are there any limitations?
Yes. For now this tool works only with SNMPv3.

## How to install?
1. Clone this repository `git clone https://github.com/STwilight/net-snmp-inventory.git` (or download [the latest release](https://github.com/STwilight/net-snmp-inventory/releases/latest) from the [releases](https://github.com/STwilight/net-snmp-inventory/releases) page).
2. Extract contents of an archive (if you're got the source code archive copy).
3. Go into project's directory: `cd net-snmp-inventory-main`.
4. Install dependencies: `pip3 install -r requirements.txt`.
5. Copy to LLDP module to Python's PySNMP MIBs folder: `cp .\pysnmp_mibs\LLDP-MIB.py <PYTHON DIR>\Lib\site-packages\pysnmp_mibs\`.

## How to use?
1. Read the help: `python3 .\net-snmp-inventory.py --help`.
2. Run the scan: `python3 .\net-snmp-inventory.py --net 192.0.2.0/24 --sec_name "snmp-user" --auth_proto sha1 --auth_passwd "authentication-pass" --priv_proto aes128 --priv_passwd "priviledged-pass"`.
3. Monitor progress in the console.
4. Get the report in working dir.
5. Enjoy 😄

## What's the plans?
- Implement report exporting to Excel in `*.xlsx` file format.
- Process additional specific attributes for other hardware vendors.
- Implement support of SNMP v1 and v2 protocol.
- Create standalone executable file.

## References
Some of MIB files for PySNMP library was copied from [thola.io](https://mibs.thola.io/pysnmp/) project (view on [Github](https://github.com/inexio/thola)).
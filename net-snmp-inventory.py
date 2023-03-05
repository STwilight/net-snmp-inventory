#!/usr/bin/python3

# An inventory tool for network equipment discovery & audit, based on ICMP PING + SNMP protocols
# Written and tested with Python 3.10 by Symrak

"""
Depend on external modules:
	pip install ping3
"""

# Importing libraries
from ping3 import ping
from ipaddress import IPv4Network

# Reading input
scanAddress = IPv4Network("192.168.1.0/29")

# Calculating the network
netAddress = scanAddress.network_address
netBroadcastAddress = scanAddress.broadcast_address
netDescription = str(netAddress) + "/" + str(scanAddress.prefixlen)
print("\nThe given network is %s (%s), consists of %s hosts." % (netDescription, scanAddress.netmask, scanAddress.num_addresses-2))

# Generating host dictionary
netScanDict = {netDescription : {}}
for hostAddress in scanAddress:
	if ((hostAddress != netAddress) and (hostAddress != netBroadcastAddress)):
		netScanDict[netDescription].update({str(hostAddress) : {"PING" : False, "SNMP" : False, "Hostname" : "N/A", "Model" : "N/A", "S/N" : "N/A", "FW" : "N/A"}})

# Performing ICMP PING host discovery
for hostAddress in netScanDict[netDescription]:
	checkResult = ping(hostAddress)
	### DEBUG: PING value output in miliseconds
	# print(round(checkResult, 2))
	netScanDict[netDescription][hostAddress]["PING"] = True if isinstance(checkResult, float) else False

# Printing out the results
print("\nThe scan results for network %s are:" % (netDescription))
for hostAddress in netScanDict[netDescription]:
	resultString = "\t " + hostAddress + ": "
	for element in netScanDict[netDescription][hostAddress]:
		resultString = resultString + element + " = " + str(netScanDict[netDescription][hostAddress][element]) + "; "
	print(resultString)

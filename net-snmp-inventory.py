#!/usr/bin/python3

# An inventory tool for network equipment discovery & audit, based on ICMP PING + SNMP protocols
# Written and tested with Python 3.10 by Symrak

"""
Depend on external modules:
	pip install ping3
	pip install pysnmp
"""

# Importing libraries
from ping3 import ping
from ipaddress import IPv4Network
import sys, socket

"""
def udp_connection(ip, port, timeout):
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
		s.settimeout(timeout)
		try:
			s.sendto(b'test', (ip, port))
			data, addr = s.recvfrom(1024)
			return "[+] UDP Port Open: " + str(port) + str(data) + '\n'
		except TimeoutError:
			return "[+] UDP Port Open | Filtered: " + str(port) + '\n'
		except:
			return "[+] UDP Port Closed: " + str(port) + '\n'

print (udp_connection("192.168.1.200", 161, 2))
sys.exit()
"""

from pysnmp.hlapi import *
auth = UsmUserData (
    userName = "SNMPv3-User",
    authKey = "authentication-pass",
    authProtocol = usmHMACSHAAuthProtocol,
    privKey = "priviledged-pass",
    privProtocol = usmAesCfb128Protocol
)
iterator = getCmd (
    SnmpEngine (),
    auth,
    UdpTransportTarget (("192.168.1.200", 161)),
    ContextData (),
    #ObjectType (ObjectIdentity('SNMPv2-MIB', 'sysName', 0))
    ObjectType(ObjectIdentity(".1.3.6.1.2.1.1.1.0")),
    ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.100.1.1.1.0")),
    lookupMib = False
)
errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
if errorIndication:
	print(errorIndication)
elif errorStatus:
	print('%s at %s' % (errorStatus.prettyPrint(),
	errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
	for varBind in varBinds:
		print(' = '.join([x.prettyPrint() for x in varBind]))
sys.exit()

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

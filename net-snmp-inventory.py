#!/usr/bin/python3

# An inventory tool for network equipment discovery & audit, based on ICMP PING + SNMP protocols
# Written and tested with Python 3.10 by Symrak

"""
Depend on external modules:
	pip install macaddress
	pip install ipaddress
	pip install ping3
	pip install pysnmp
	pip install pysnmp-mibs
"""

# Importing libraries
from ping3 import ping
from ipaddress import IPv4Address, IPv4Network
import sys, socket, macaddress

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
from pysnmp.smi.rfc1902 import ObjectIdentity

snmpHost = "192.168.1.200"
snmpPort = 161
snmpIterMaxCount = 256
snmpAuth = UsmUserData (
    userName = "SNMPv3-User",
    authKey = "authentication-pass",
    authProtocol = usmHMACSHAAuthProtocol,
    privKey = "priviledged-pass",
    privProtocol = usmAesCfb128Protocol
)

### SNMP GET REQUESTS
snmpRequest = getCmd (
    SnmpEngine (),
    snmpAuth,
    UdpTransportTarget ((snmpHost, snmpPort)),
    ContextData (),
	## System Name @ sysName!@#.iso.org.dod.internet.mgmt.mib-2.system.sysName (.1.3.6.1.2.1.1.5.0)
	ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0)),
	## Manufacturer @ entPhysicalMfgName!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalMfgName
	ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalMfgName", 1)),
	## Model @ entPhysicalName!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalName
	ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalModelName", 1)),
	## Software Version @ fgSysVersion!@#.iso.org.dod.internet.private.enterprises.fortinet.fnFortiGateMib.fgSystem.fgSystemInfo.fgSysVersion
	ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.101.4.1.1.0")),
	## Software Revision @ entPhysicalSoftwareRev!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSoftwareRev
	# ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSoftwareRev", 1)),
	## Serial Number @ entPhysicalSerialNum!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSerialNum
	ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSerialNum", 1)),
	## Serial Number @ fnSysSerial!@#.iso.org.dod.internet.private.enterprises.fortinet.fnCoreMib.fnCommon.fnSystem.fnSysSerial
	# ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.100.1.1.1.0")),
	## Location @ sysLocation!@#.iso.org.dod.internet.mgmt.mib-2.system.sysLocation (.1.3.6.1.2.1.1.6.0)
	ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
    ## Description @ sysDescr!@#.iso.org.dod.internet.mgmt.mib-2.system.sysDescr (.1.3.6.1.2.1.1.1.0)
	ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
	## Contact @ sysContact!@#.iso.org.dod.internet.mgmt.mib-2.system.sysContact (.1.3.6.1.2.1.1.4.0)
	ObjectType(ObjectIdentity("SNMPv2-MIB", "sysContact", 0)),
    lookupMib = True,
	lexicographicMode = False
)
errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
if errorIndication:
	print(errorIndication)
elif errorStatus:
	print("%s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
else:
	for varBind in varBinds:
		print(" = ".join([x.prettyPrint() for x in varBind]))
		name, value = varBind
		print("\tOID = %s" % name)
		print("\tValue = %s" % value)

### SNMP GET-NEXT REQUESTS
## MAC Address
snmpRequest = nextCmd (
    SnmpEngine (),
    snmpAuth,
    UdpTransportTarget ((snmpHost, snmpPort)),
    ContextData (),
	## MAC Address @ ifPhysAddress!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifPhysAddress
	ObjectType(ObjectIdentity(".1.3.6.1.2.1.2.2.1.6")),
    lookupMib = True,
	lexicographicMode = False
)
errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
if errorIndication:
	print(errorIndication)
elif errorStatus:
	print("%s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
else:
	for varBind in varBinds:
		print(" = ".join([x.prettyPrint() for x in varBind]))
		name, value = varBind
		print("\tOID = %s" % name)
		print("\tValue = %s" % str(macaddress.MAC(bytes(value))).replace('-', ':'))
## IP Addresses
snmpRequest = nextCmd (
    SnmpEngine (),
    snmpAuth,
    UdpTransportTarget ((snmpHost, snmpPort)),
    ContextData (),
	## IP Addresses @ ipAdEntAddr!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable.ipAddrEntry.ipAdEntAddr
	ObjectType(ObjectIdentity("IP-MIB", "ipAdEntAddr")),
    lookupMib = True,
	lexicographicMode = False
)
snmpIterCount = 0
while(snmpIterCount < snmpIterMaxCount):
	try:
		errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
		if errorIndication:
			print(errorIndication)
		elif errorStatus:
			print("%s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
		else:
			for varBind in varBinds:
				print(" = ".join([x.prettyPrint() for x in varBind]))
				name, value = varBind
				print("\tOID = %s" % name)
				print("\tIP = %s" % IPv4Address(value.asOctets()))
		snmpIterCount += 1
	except StopIteration:
		break
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
		netScanDict[netDescription].update({str(hostAddress) : {"Sysname" : "N/A", "Manufacturer" : "N/A", "Model" : "N/A", "FW" : "N/A",
																"S/N" : "N/A", "Location" : "N/A", "Description" : "N/A", "Contact" : "N/A",
																"MAC Address" : "N/A", "IP Addresses" : [], "PING" : False, "SNMP" : False}})

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

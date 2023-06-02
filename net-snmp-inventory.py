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
from pysnmp.hlapi import *
from pysnmp.smi.rfc1902 import ObjectIdentity
from ipaddress import IPv4Address, IPv4Network
import sys, socket, macaddress

# Reading input
scanAddress = IPv4Network("192.168.1.192/28")
# snmpHost = "192.168.1.200"
snmpPort = 161
snmpIterMaxCount = 256
snmpRetriesCount = 0
snmpTimeout = 2.0
snmpUsername = "SNMPv3-User"
snmpAuthKey = "authentication-pass"
snmpAuthProtocol = usmHMACSHAAuthProtocol
snmpPrivKey = "priviledged-pass"
snmpPrivProtocol = usmAesCfb128Protocol


# Functions definitions
"""
def udp_connection(ip, port, timeout):
	# Checking UDP port availability
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

def snmp_audit(snmpHost, snmpUsername, snmpAuthKey, snmpPrivKey, snmpAuthProtocol=usmHMACSHAAuthProtocol, snmpPrivProtocol=usmAesCfb128Protocol, snmpPort=161, snmpIterMaxCount=256, snmpRetriesCount=0, snmpTimeout=2.0):
	# Function variables
	snmpDataDict = {snmpHost : {"Sysname" : None, "Manufacturer" : None, "Model" : None, "FW" : None,
																"S/N" : None, "Location" : None, "Description" : None, "Contact" : None,
																"MAC Address" : None, "IP Addresses" : [], "PING" : True, "SNMP" : False}}
	# Authentication data
	snmpAuth = UsmUserData (
		userName = snmpUsername,
		authKey = snmpAuthKey,
		authProtocol = snmpAuthProtocol,
		privKey = snmpPrivKey,
		privProtocol = snmpPrivProtocol
	)
	# SNMP GET requests payload & processing
	# General information collecting
	snmpRequest = getCmd (
		SnmpEngine (),
		snmpAuth,
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=snmpTimeout),
		ContextData (),
		# System Name @ sysName!@#.iso.org.dod.internet.mgmt.mib-2.system.sysName (.1.3.6.1.2.1.1.5.0)
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0)),
		# Manufacturer @ entPhysicalMfgName!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalMfgName
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalMfgName", 1)),
		# Model @ entPhysicalName!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalName
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalModelName", 1)),
		# Software Version @ fgSysVersion!@#.iso.org.dod.internet.private.enterprises.fortinet.fnFortiGateMib.fgSystem.fgSystemInfo.fgSysVersion
		ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.101.4.1.1.0")),
		### ALTERNATIVE REQUEST: FW Version
		# Software Revision @ entPhysicalSoftwareRev!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSoftwareRev
		# ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSoftwareRev", 1)),
		# Serial Number @ entPhysicalSerialNum!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSerialNum
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSerialNum", 1)),
		### ALTERNATIVE REQUEST: Serial Number
		# Serial Number @ fnSysSerial!@#.iso.org.dod.internet.private.enterprises.fortinet.fnCoreMib.fnCommon.fnSystem.fnSysSerial
		# ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.100.1.1.1.0")),
		# Location @ sysLocation!@#.iso.org.dod.internet.mgmt.mib-2.system.sysLocation (.1.3.6.1.2.1.1.6.0)
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
		# Description @ sysDescr!@#.iso.org.dod.internet.mgmt.mib-2.system.sysDescr (.1.3.6.1.2.1.1.1.0)
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
		# Contact @ sysContact!@#.iso.org.dod.internet.mgmt.mib-2.system.sysContact (.1.3.6.1.2.1.1.4.0)
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysContact", 0)),
		lookupMib = True,
		lexicographicMode = False
	)
	errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
	if errorIndication:
		print("\t[WARN!] IP %s [SNMP - General Info] - %s" % (snmpHost, errorIndication))
	elif errorStatus:
		print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
	else:
		# Array for storing SNMP values
		varBindValues = []
		# Extracting SNMP OIDs and their Values
		for varBind in varBinds:
			### DEBUG: Pretty output of SNMP library
			# print(" = ".join([x.prettyPrint() for x in varBind]))
			name, value = varBind
			varBindValues.append(str(value))
			### DEBUG: OID and value output
			# print("\tOID = %s" % name)
			# print("\tValue = %s" % value)
		# Filling-ip dictionary with array values
		valuesCount = len(varBindValues)
		i = 0
		for key in snmpDataDict[snmpHost]:
			if ((varBindValues[i]) != None and len(varBindValues[i]) > 0):
				snmpDataDict[snmpHost][key] = varBindValues[i]
			if i < valuesCount-1:
				i += 1
			else:
				break
		# Flipping SNMP state flag
		snmpDataDict[snmpHost]["SNMP"] = True
	# SNMP GET-NEXT requests payload & processing
	# MAC address collecting (only interface #1)
	snmpRequest = nextCmd (
		SnmpEngine (),
		snmpAuth,
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=snmpTimeout),
		ContextData (),
		# MAC Address @ ifPhysAddress!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifPhysAddress
		ObjectType(ObjectIdentity(".1.3.6.1.2.1.2.2.1.6")),
		lookupMib = True,
		lexicographicMode = False
	)
	errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
	if errorIndication:
		print("\t[WARN!] IP %s [SNMP - MAC Addresses] - %s" % (snmpHost, errorIndication))
	elif errorStatus:
		print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
	else:
		# Extracting SNMP OIDs and their Values
		for varBind in varBinds:
			### DEBUG: Pretty output of SNMP library
			# print(" = ".join([x.prettyPrint() for x in varBind]))
			name, value = varBind
			snmpDataDict[snmpHost]["MAC Address"] = str(macaddress.MAC(bytes(value))).replace("-", ":").lower()
			### DEBUG: OID and MAC value output
			# print("\tOID = %s" % name)
			# print("\tValue = %s" % str(macaddress.MAC(bytes(value))).replace("-", ":"))
		# Flipping SNMP state flag
		snmpDataDict[snmpHost]["SNMP"] = True
	# IP address collecting (all available)
	snmpRequest = nextCmd (
		SnmpEngine (),
		snmpAuth,
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=snmpTimeout),
		ContextData (),
		# IP Addresses @ ipAdEntAddr!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable.ipAddrEntry.ipAdEntAddr
		ObjectType(ObjectIdentity("IP-MIB", "ipAdEntAddr")),
		lookupMib = True,
		lexicographicMode = False
	)
	snmpIterCount = 0
	while(snmpIterCount < snmpIterMaxCount):
		try:
			errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
			if errorIndication:
				print("\t[WARN!] IP %s [SNMP - IP Addresses] - %s" % (snmpHost, errorIndication))
			elif errorStatus:
				print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
			else:
				# Extracting SNMP OIDs and their Values
				for varBind in varBinds:
					### DEBUG: Pretty output of SNMP library
					# print(" = ".join([x.prettyPrint() for x in varBind]))
					name, value = varBind
					snmpDataDict[snmpHost]["IP Addresses"].append(str(IPv4Address(value.asOctets())))
					### DEBUG: OID and IP value output
					# print("\tOID = %s" % name)
					# print("\tIP = %s" % IPv4Address(value.asOctets()))
			snmpIterCount += 1
		except StopIteration:
			break
	# Filling-ip IP address with None if there are no any addresses
	if len(snmpDataDict[snmpHost]["IP Addresses"]) == 0:
		snmpDataDict[snmpHost]["IP Addresses"] = None
	else:
		# Flipping SNMP state flag
		snmpDataDict[snmpHost]["SNMP"] = True
	return snmpDataDict

# Calculating the network
netAddress = scanAddress.network_address
netBroadcastAddress = scanAddress.broadcast_address
netDescription = str(netAddress) + "/" + str(scanAddress.prefixlen)
netAddressesCount = scanAddress.num_addresses-2
print("\nThe given network is %s (%s), consists of %s hosts.\n" % (netDescription, scanAddress.netmask, netAddressesCount))

# Generating host dictionary
netScanDict = {netDescription : {}}
for hostAddress in scanAddress:
	if ((hostAddress != netAddress) and (hostAddress != netBroadcastAddress)):
		netScanDict[netDescription].update({str(hostAddress) : {"Sysname" : None, "Manufacturer" : None, "Model" : None, "FW" : None,
																"S/N" : None, "Location" : None, "Description" : None, "Contact" : None,
																"MAC Address" : None, "IP Addresses" : None, "PING" : False, "SNMP" : False}})

# Performing host discovery & SNMP audit
currentAddressNumber = 1
print("Scanning hosts (ICMP PING discovery + SNMP requests):")
for hostAddress in netScanDict[netDescription]:
	# Performing ICMP PING host discovery
	print("\tProgress: IP %s [PING] - %s of %s (%.2f%%)" % (hostAddress, currentAddressNumber, netAddressesCount, currentAddressNumber/netAddressesCount*100), end="\r")
	checkResult = ping(hostAddress)
	### DEBUG: PING value output in miliseconds
	# print(round(checkResult, 2))
	hostIsActive = True if isinstance(checkResult, float) else False
	netScanDict[netDescription][hostAddress]["PING"] = hostIsActive
	# Performing SNMP host audit
	if hostIsActive:
		print("\tProgress: IP %s [SNMP] - %s of %s (%.2f%%)" % (hostAddress, currentAddressNumber, netAddressesCount, currentAddressNumber/netAddressesCount*100), end="\r")
		netScanDict[netDescription].update(snmp_audit(hostAddress, snmpUsername, snmpAuthKey, snmpPrivKey, snmpAuthProtocol, snmpPrivProtocol, snmpPort, snmpIterMaxCount, snmpRetriesCount, snmpTimeout))
	# Incrementing address number
	currentAddressNumber += 1

# Printing out the results
print("\n\nThe scan results for network %s are:" % (netDescription))
for hostAddress in netScanDict[netDescription]:
	resultString = "\t " + hostAddress + ": "
	for element in netScanDict[netDescription][hostAddress]:
		resultString = resultString + element + " = " + str(netScanDict[netDescription][hostAddress][element]) + "; "
	print(resultString)
print("\n")

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
	pip install argumentparser
	# Based on link (https://stackoverflow.com/a/76196943) we need PyASN1 of version <= 0.4.8
	pip install pyasn1==0.4.8
"""

# Importing libraries
from os import path
from sys import exit
from math import modf
from ping3 import ping
from pysnmp.hlapi import *
from datetime import datetime
from argparse import ArgumentParser
from pysnmp.smi.rfc1902 import ObjectIdentity
from ipaddress import IPv4Address, IPv4Network
import time, macaddress, platform

# Get script name and working directory
scriptName = path.basename(__file__)
dirName = path.dirname(path.realpath(__file__))

# Determinating path delimiter symbol based on OS type (Windows or Linux)
pathDelimiter = "\\" if platform.system() == "Windows" else "/"

# Parsing the arguments
argParser = ArgumentParser(prog = scriptName,
	description = "NetSNMP Inventory Tool: an inventory tool for network equipment discovery & audit")
argParser.add_argument("-net", "--network", required=True, type=str, metavar="192.0.2.0/24", dest="netAddress",
	help="Network address for scanning with CIDR netmask (e.g. 192.0.2.0/24)")
argParser.add_argument("-p", "--port", required=False, type=int, default=161, choices=range(1, 65536), metavar="{1 .. 65535}", dest="snmpPort",
	help="SNMP service port number (default is 161)")

argParser.add_argument("-empty", "--emptyvalue", required=False, type=str, default="N/A", metavar="\"N/A\"", dest="emptyValue",
	help="Empty value for the report (default is \"N/A\")")
argParser.add_argument("-csvdel", "--csvdelimiter", required=False, type=str, default=";", metavar="\";\"", dest="csvDelimiter",
	help="Delimiter value for the CSV report (default is \";\")")
scriptArgs = argParser.parse_args()

# Processing input data
try:
	scanAddress = IPv4Network(scriptArgs.netAddress)
except ValueError:
	print("\nNetwork address is incorrect!\n")
	exit()
reportEmptyValue = scriptArgs.emptyValue
csvReportDelimeter = scriptArgs.csvDelimiter
snmpPort = scriptArgs.snmpPort
snmpIterMaxCount = 256
snmpRetriesCount = 0
snmpTimeout = 2.0
snmpUsername = "SNMPv3-User"
snmpAuthKey = "authentication-pass"
snmpAuthProtocol = usmHMACSHAAuthProtocol
snmpPrivKey = "priviledged-pass"
snmpPrivProtocol = usmAesCfb128Protocol
outFilePath = dirName + pathDelimiter + datetime.today().strftime("%Y-%m-%d") + " – net-audit-report_net-" + str(scanAddress).replace("/", "_cidr-") + ".csv"

# General variables
dataDictTemplate = {"Sysname" : None, "Manufacturer" : None, "Model" : None, "FW" : None,
					"S/N" : None, "Location" : None, "Description" : None, "Contact" : None, "Comment" : None,
					"MAC Address" : None, "IP Addresses" : None, "PING" : False, "SNMP" : False}

# Functions definitions
"""
import socket
# Checking UDP port availability
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
exit()
"""

# Collecting SNMP data
def snmp_audit(snmpHost, snmpUsername, snmpAuthKey, snmpPrivKey, dataDict, valuesDelimeter=";", snmpAuthProtocol=usmHMACSHAAuthProtocol, snmpPrivProtocol=usmAesCfb128Protocol, snmpPort=161, snmpIterMaxCount=256, snmpRetriesCount=0, snmpTimeout=2.0):
	# Function variables
	snmpDataDict = {snmpHost : dataDict.copy()}
	snmpDataDict[snmpHost]["IP Addresses"] = []
	snmpDataDict[snmpHost]["PING"] = True
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
		# Software Revision @ entPhysicalSoftwareRev!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSoftwareRev
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSoftwareRev", 1)),
		# Serial Number @ entPhysicalSerialNum!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSerialNum
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSerialNum", 1)),
		# Location @ sysLocation!@#.iso.org.dod.internet.mgmt.mib-2.system.sysLocation
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
		# Description @ sysDescr!@#.iso.org.dod.internet.mgmt.mib-2.system.sysDescr
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
		# Contact @ sysContact!@#.iso.org.dod.internet.mgmt.mib-2.system.sysContact
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysContact", 0)),
		# System logical description @ entLogicalDescr!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityLogical.entLogicalTable.entLogicalEntry.entLogicalDescr
		ObjectType(ObjectIdentity("ENTITY-MIB", "entLogicalDescr", 1)),
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
			value = str(value).replace("\n\r", " ")
			value = str(value).replace("\n", " ")
			value = str(value).replace("\r", " ")
			value = str(value).replace(valuesDelimeter, " ")
			varBindValues.append(value)
			### DEBUG: OID and value output
			# print("\tOID = %s" % name)
			# print("\tValue = %s" % value)
		# Filling-up dictionary with array values
		valuesCount = len(varBindValues)
		i = 0
		for key in snmpDataDict[snmpHost]:
			value = varBindValues[i]
			if ((value) != None and len(value) > 0):
				snmpDataDict[snmpHost][key] = value
			if i < valuesCount-1:
				i += 1
			else:
				break
		# Flipping SNMP state flag
		snmpDataDict[snmpHost]["SNMP"] = True
	# Vendor-specific information collecting
	# Forinet Fortigate
	if snmpDataDict[snmpHost]["Manufacturer"] == "Fortinet":
		# FortiGate devices
		if (("FortiGate" in snmpDataDict[snmpHost]["Comment"]) or ("FortiGate" in snmpDataDict[snmpHost]["FW"])):
			snmpRequest = getCmd (
				SnmpEngine (),
				snmpAuth,
				UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=snmpTimeout),
				ContextData (),
				# FortiGate Software Version @ fgSysVersion!@#.iso.org.dod.internet.private.enterprises.fortinet.fnFortiGateMib.fgSystem.fgSystemInfo.fgSysVersion
				ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.101.4.1.1.0")),	
				# FortiGate Serial Number @ fnSysSerial!@#.iso.org.dod.internet.private.enterprises.fortinet.fnCoreMib.fnCommon.fnSystem.fnSysSerial
				ObjectType(ObjectIdentity(".1.3.6.1.4.1.12356.100.1.1.1.0")),
				lookupMib = True,
				lexicographicMode = False
			)
			errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
			if errorIndication:
				print("\t[WARN!] IP %s [SNMP - Vendor Info] - %s" % (snmpHost, errorIndication))
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
					varBindValues.append(str(value).replace("\n", " "))
					### DEBUG: OID and value output
					# print("\tOID = %s" % name)
					# print("\tValue = %s" % value)
				# Re-filling some dictionary values with array values
				keysDictionary = {0 : "FW", 1 : "S/N"}
				for arrayKey, dictKey in keysDictionary.items():
					value = varBindValues[arrayKey]
					if ((value) != None and len(value) > 0):
						snmpDataDict[snmpHost][dictKey] = value
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
					snmpDataDict[snmpHost]["IP Addresses"].append(IPv4Address(value.asOctets()))
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

# Converting an execution time into human readable format
def convertTime(timeInSeconds):
	if not timeInSeconds == None:
		if timeInSeconds >= 0:
			frac, days = modf(timeInSeconds/86400)
			frac, hours = modf((frac*86400)/3600)
			frac, minutes = modf((frac*3600)/60)
			frac, seconds = modf((frac*60))
			return ("%d day(s) %d hour(s) %d min(s) and %d second(s)" % (days, hours, minutes, seconds))
	return ("N/A")

# CSV generation function
def generateCSVReport(inputDict, netAddress, templateDict, csvDelimeter=",", emptyValue="N/A"):
	# Processing data
	reportContent = ""
	### HEADER DATA
	if ((templateDict != None) and isinstance(templateDict, dict) and (len(templateDict)) > 0):
		# Generating header row
		csvFileHeader = ["Network", "Host"]
		# Parsing columns data array
		for key in templateDict:
			csvFileHeader.append(key)
		# Filling table header row with data
		csvRowData = ""
		for value in csvFileHeader:
			csvRowData += value + csvDelimeter
		csvRowData = csvRowData.removesuffix(csvDelimeter)
		csvRowData += "\n"
		reportContent += csvRowData
	### CONTENT DATA
	# Filling table rows with data
	if ((inputDict != None) and isinstance(inputDict, dict) and (len(inputDict)) > 0):
		for host in inputDict:
			csvRowData = ""
			# Injecting additional columns into CSV
			csvRowData += netAddress + csvDelimeter
			csvRowData += host + csvDelimeter
			# Processing multiple values from dictionary
			for element in inputDict[host]:
				# Processing multiple IP addresses values
				if (element == "IP Addresses" and inputDict[host][element] != None):
					elementValue = ""
					for ipAddress in inputDict[host][element]:
						elementValue += str(ipAddress) + ", "
					elementValue = elementValue.removesuffix(", ")
				# Processing any non-zero values
				elif inputDict[host][element] != None:
					elementValue = str(inputDict[host][element])
				# None-values processing
				else:
					elementValue = emptyValue
				csvRowData += elementValue + csvDelimeter
			csvRowData = csvRowData.removesuffix(csvDelimeter)
			csvRowData += "\n"
			reportContent += csvRowData
	return reportContent

# Function for flushing content from memory to file
def flushMemContentToFile(filePath, memContent):
	if memContent == None:
		print("Nothing to flush to file!")
		sys.exit()		
	else:
		try:
			print("Flushing to file \"%s\"..." % filePath)
			file = open(filePath, "w+", encoding="utf8")
			file.writelines(memContent)
			file.close()
		except:
			print("Failed to flush to output file!")
			sys.exit()

### Main code block
# Determinating the time of start	
startTime = time.time()

# Calculating the network
netAddress = scanAddress.network_address
netBroadcastAddress = scanAddress.broadcast_address
netPrefixLen = scanAddress.prefixlen
netDescription = str(netAddress) + "/" + str(netPrefixLen)
netAddressesCount = 1 if (netPrefixLen == 32) else (scanAddress.num_addresses - 2)
print("\nThe given network is %s (%s), consists of %d host(s).\n" % (netDescription, scanAddress.netmask, netAddressesCount))
if netAddressesCount <= 0:
	print("There are no hosts to scan! Exiting...\n")
	exit()

# Generating host dictionary
netScanDict = {netDescription : {}}
if netPrefixLen == 32:
	hostAddress = netAddress
	netScanDict[netDescription].update({str(hostAddress) : dataDictTemplate.copy()})
else:
	for hostAddress in scanAddress:
		if ((hostAddress != netAddress) and (hostAddress != netBroadcastAddress)):
			netScanDict[netDescription].update({str(hostAddress) : dataDictTemplate.copy()})

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
		print("\tProgress: IP %s [SNMP] - %d of %d (%.2f%%)" % (hostAddress, currentAddressNumber, netAddressesCount, currentAddressNumber/netAddressesCount*100), end="\r")
		netScanDict[netDescription].update(snmp_audit(hostAddress, snmpUsername, snmpAuthKey, snmpPrivKey, dataDictTemplate, csvReportDelimeter, snmpAuthProtocol, snmpPrivProtocol, snmpPort, snmpIterMaxCount, snmpRetriesCount, snmpTimeout))
	# Incrementing address number
	currentAddressNumber += 1

# Printing out the results
print("\n\nThe scan results for network %s are:" % (netDescription))
for hostAddress in netScanDict[netDescription]:
	resultString = "\t " + hostAddress + ": "
	for element in netScanDict[netDescription][hostAddress]:
		# Processing multiple IP addresses values
		if (element == "IP Addresses" and netScanDict[netDescription][hostAddress][element] != None):
			elementValue = ""
			# IP addresses arrays
			for ipAddress in netScanDict[netDescription][hostAddress][element]:
				elementValue += str(ipAddress) + ", "
			elementValue = elementValue.removesuffix(", ")
		# Any non-zero values
		elif netScanDict[netDescription][hostAddress][element] != None:
			elementValue = str(netScanDict[netDescription][hostAddress][element])
		# None-values
		else:
			elementValue = reportEmptyValue
		resultString = resultString + element + " = " + elementValue + "; "
	print(resultString.removesuffix(" "))

# Determinating the time of end
endTime = time.time()

# Statistic printing and exiting
print("\n%d hosts have been scanned in %s." % (netAddressesCount, convertTime(endTime-startTime)))
print()

# Generating CSV file content
outFileContent = generateCSVReport(netScanDict[netDescription], netDescription, dataDictTemplate, csvReportDelimeter, reportEmptyValue)

### DEBUG: CSV report printing
# print("Results output in CSV format:")
# print(outFileContent)

# Flushing data into file
print("Exporting CSV report into file...")
flushMemContentToFile(outFilePath, outFileContent)

print("\nDone!\n")

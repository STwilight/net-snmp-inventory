#!/usr/bin/python3
# coding=utf-8

# An inventory tool for network equipment discovery & audit, based on ICMP PING + SNMP protocols.
# Depends on external modules (see requirements.txt).

# Special script values
__author__ = "Symrak"
__version__ = "0.2"
__min_python__ = (3, 10)

# Importing libraries
from copy import deepcopy
from os import path, makedirs
from sys import version_info, exit
from math import modf
from ping3 import ping
from pysnmp.hlapi import *
from datetime import datetime
from argparse import ArgumentParser
from pysnmp.smi.rfc1902 import ObjectIdentity
from ipaddress import IPv4Address, IPv4Network
from netaddr import IPAddress
import time, macaddress, platform

# Check Python version
if version_info < __min_python__:
    exit("\nPython %s.%s or later is required! Exiting...\n" % __min_python__)

# Get script name and working directory
scriptName = path.basename(__file__)
dirName = path.dirname(path.realpath(__file__))

# Determinating path delimiter symbol based on OS type (Windows or Linux)
pathDelimiter = "\\" if platform.system() == "Windows" else "/"

# Parsing the arguments
argParser = ArgumentParser(prog = scriptName,
	description = "NetSNMP Inventory Tool: utility for network equipment discovery & audit (v" + __version__ + " by " + __author__ + ").")
argParser.add_argument("-r", "--net", required=True, type=str, metavar="192.0.2.0/24", dest="netAddress",
	help="Network address with CIDR netmask. Example: 192.0.2.0/24")
argParser.add_argument("-sn", "--sec_name", required=True, type=str, metavar="\"snmp-user\"", dest="snmpUsername",
	help="SNMP security name (SNMPv3).")
argParser.add_argument("-ap", "--auth_proto", required=False, type=str, default="sha1", choices=["none","md5","sha1","sha224","sha256","sha384","sha512"], metavar="sha1", dest="snmpAuthProtocol",
	help="Authentication protocol (in lowercase). Supported: NONE, MD5, SHA1, SHA224, SHA256, SHA384, SHA512 (SNMPv3).")
argParser.add_argument("-aw", "--auth_passwd", required=False, type=str, metavar="\"auth-pass\"", dest="snmpAuthKey",
	help="Authentication password (SNMPv3).")
argParser.add_argument("-pp", "--priv_proto", required=False, type=str, default="aes128", choices=["none","des","3des","aes128","aes192","aes192b","aes256","aes256b"], metavar="aes128", dest="snmpPrivProtocol",
	help="Privacy protocol (in lowercase). Supported: NONE, DES, 3DES, AES128, AES192, AES192 Blumenthal, AES256, AES256 Blumenthal (SNMPv3).")
argParser.add_argument("-pw", "--priv_passwd", required=False, type=str, metavar="\"privacy-pass\"", dest="snmpPrivKey",
	help="Privacy password (SNMPv3).")
argParser.add_argument("-p", "--port", required=False, type=int, default=161, choices=range(1, 65536), metavar="(1 .. 65535)", dest="snmpPort",
	help="SNMP port number on remote host. Default: 161")
argParser.add_argument("-il", "--iter_lim", required=False, type=int, default=256, choices=[1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384], metavar="(1, 2, 4 .. 8192, 16384)", dest="snmpIterMaxCount",
	help="SNMP values limit for iterable objects. Default: 256")
argParser.add_argument("-rc", "--ret_cnt", required=False, type=int, default=0, choices=range(0, 10), metavar="(0 .. 9)", dest="snmpRetriesCount",
	help="SNMP request retries count. Default: 0")
argParser.add_argument("-t", "--timeout", required=False, type=int, default=5, choices=range(0, 601), metavar="(0 .. 600)", dest="snmpTimeout",
	help="SNMP timeout in seconds. Default: 5")
argParser.add_argument("-ip", "--ign_ping", action="store_true", dest="ignorePingFlag",
	help="Ignore results of an ICMP PING scan (check every host using SNMP requests).")
argParser.add_argument("-out", "--reports_dir", required=False, type=str, metavar=".\reports\\", dest="outDirPath",
	help="Path to reports output directory. Default: autogenerated in \"reports\" subdirectory of work directory.")
argParser.add_argument("-dm", "--csv_delim", required=False, type=str, default=";", metavar="\";\"", dest="csvReportDelimeter",
	help="Delimiter symbol for the CSV report. Default: \";\").")
argParser.add_argument("-ev", "--empty_val", required=False, type=str, default="N/A", metavar="\"N/A\"", dest="reportEmptyValue",
	help="Empty value representation. Default: \"N/A\").")
argParser.add_argument("-v", "--verbose", action="store_true", dest="verbScanProgressFlag",
	help="Additional console output while scanning SNMP.")
argParser.add_argument("-sr", "--scan_res", action="store_true", dest="scanResultsOutputFlag",
	help="Output scan results in console (in text view).")
scriptArgs = argParser.parse_args()

# Processing input data
try:
	scanAddress = IPv4Network(scriptArgs.netAddress)
except ValueError:
	print("\nNetwork address is incorrect!\n")
	exit()
reportEmptyValue = scriptArgs.reportEmptyValue
csvReportDelimeter = scriptArgs.csvReportDelimeter
snmpPort = scriptArgs.snmpPort
snmpIterMaxCount = scriptArgs.snmpIterMaxCount
snmpRetriesCount = scriptArgs.snmpRetriesCount
snmpTimeout = scriptArgs.snmpTimeout
snmpUsername = scriptArgs.snmpUsername
snmpAuthProtoDict = {"none" : usmNoAuthProtocol, "md5" : usmHMACMD5AuthProtocol,
					 "sha1" : usmHMACSHAAuthProtocol, "sha224" : usmHMAC128SHA224AuthProtocol,
					 "sha256" : usmHMAC192SHA256AuthProtocol, "sha384" : usmHMAC256SHA384AuthProtocol,
					 "sha512" : usmHMAC384SHA512AuthProtocol}
snmpAuthProtocol = snmpAuthProtoDict[scriptArgs.snmpAuthProtocol]
snmpAuthKey = scriptArgs.snmpAuthKey
snmpPrivProtoDict = {"none" : usmNoPrivProtocol, "des" : usmDESPrivProtocol,
					 "3des" : usm3DESEDEPrivProtocol, "aes128" : usmAesCfb128Protocol,
					 "aes192" : usmAesCfb192Protocol, "aes192b" : usmAesBlumenthalCfb192Protocol,
					 "aes256" : usmAesCfb256Protocol, "aes256b" : usmAesBlumenthalCfb256Protocol}
snmpPrivProtocol = snmpPrivProtoDict[scriptArgs.snmpPrivProtocol]
snmpPrivKey = scriptArgs.snmpPrivKey
ignorePingFlag = scriptArgs.ignorePingFlag
verbScanProgressFlag = scriptArgs.verbScanProgressFlag
scanResultsOutputFlag = scriptArgs.scanResultsOutputFlag

# Determinating ouput filepath
reportsDirName = "reports"
outDirPath = (dirName + pathDelimiter + reportsDirName + pathDelimiter) if scriptArgs.outDirPath == None else scriptArgs.outDirPath
### DEBUG: reports directory path output
# print(outDirPath)
# Check and create (if absent) reports directory
if not path.exists(outDirPath):
	# Trying to create reports directory
	try:
		makedirs(outDirPath)
	except:
		print("Failed to create reports directory!")
		sys.exit()

# General variables
deviceDictTemplate  = {"Sysname" : None, "Manufacturer" : None, "Model" : None, "FW" : None,
					   "S/N" : None, "Location" : None, "Description" : None, "Contact" : None, "Comment" : None,
					   "Interfaces Count" : None, "MAC Address" : None, "IP Addresses" : None, "PING" : False, "SNMP" : False}
networkDictTemplate = {"Name" : None, "Alias" : None, "Description" : None,
					   "Type" : None, "MTU" : None, "MAC Address" : None, "IP Address" : None, "Netmask" : None, "CIDR" : None,
					   "Route Network" : None, "Route Mask" : None, "Route CIDR" : None, "Admin Status" : None, "Operation Status" : None}
templatesDict = {"Device" : deviceDictTemplate.copy(), "Network" : networkDictTemplate.copy()}
templatesDict.update({"Summary" : {"Device" : templatesDict["Device"].copy(), "Network" : {}}})

# Functions definitions
# Collecting SNMP data
def snmpAudit(snmpHost, pingStatus, snmpUsername, snmpAuthKey, snmpPrivKey, summDictTempl, intDictTempl, valuesDelimeter=";", snmpAuthProtocol=usmHMACSHAAuthProtocol, snmpPrivProtocol=usmAesCfb128Protocol, snmpPort=161, snmpIterMaxCount=256, snmpRetriesCount=0, snmpTimeout=5):
	# Function variables
	snmpDataDict = {snmpHost : deepcopy(summDictTempl)}
	snmpDataDict[snmpHost]["Device"]["IP Addresses"] = []
	snmpDataDict[snmpHost]["Device"]["PING"] = pingStatus
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
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=float(snmpTimeout)),
		ContextData (),
		# System name @ sysName!@#.iso.org.dod.internet.mgmt.mib-2.system.sysName (.1.3.6.1.2.1.1.5.0)
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0)),
		# Manufacturer @ entPhysicalMfgName!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalMfgName
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalMfgName", 1)),
		# Model @ entPhysicalName!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalName
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalModelName", 1)),
		# Software revision @ entPhysicalSoftwareRev!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSoftwareRev
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSoftwareRev", 1)),
		# Serial number @ entPhysicalSerialNum!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityPhysical.entPhysicalTable.entPhysicalEntry.entPhysicalSerialNum
		ObjectType(ObjectIdentity("ENTITY-MIB", "entPhysicalSerialNum", 1)),
		# Location @ sysLocation!@#.iso.org.dod.internet.mgmt.mib-2.system.sysLocation
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
		# Description @ sysDescr!@#.iso.org.dod.internet.mgmt.mib-2.system.sysDescr
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
		# Contact @ sysContact!@#.iso.org.dod.internet.mgmt.mib-2.system.sysContact
		ObjectType(ObjectIdentity("SNMPv2-MIB", "sysContact", 0)),
		# System logical description @ entLogicalDescr!@#.iso.org.dod.internet.mgmt.mib-2.entityMIB.entityMIBObjects.entityLogical.entLogicalTable.entLogicalEntry.entLogicalDescr
		ObjectType(ObjectIdentity("ENTITY-MIB", "entLogicalDescr", 1)),
		# Interfaces count @ ifNumber!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifNumber
		ObjectType(ObjectIdentity("IF-MIB", "ifNumber", 0)),
		lookupMib = True,
		lexicographicMode = False
	)
	errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
	if errorIndication:
		if verbScanProgressFlag:
			print("\t[WARN!] IP %s [SNMP - General Info] - %s" % (snmpHost, errorIndication))
	elif errorStatus:
		print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
	else:
		# Array for storing SNMP values
		varBindValues = []
		# Extracting SNMP OIDs and their values
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
		for key in snmpDataDict[snmpHost]["Device"]:
			value = varBindValues[i]
			if ((value) != None and len(value) > 0):
				snmpDataDict[snmpHost]["Device"][key] = value
			if i < valuesCount-1:
				i += 1
			else:
				break
		# Changing SNMP iteration count based on interfaces count
		snmpIterMaxCount = snmpDataDict[snmpHost]["Device"]["Interfaces Count"] if isinstance(snmpDataDict[snmpHost]["Device"]["Interfaces Count"], int) else scriptArgs.snmpIterMaxCount
		# Flipping SNMP state flag
		snmpDataDict[snmpHost]["Device"]["SNMP"] = True
	# Vendor-specific information collecting
	# Forinet Fortigate
	if snmpDataDict[snmpHost]["Device"]["Manufacturer"] == "Fortinet":
		# FortiGate devices
		if (("FortiGate" in snmpDataDict[snmpHost]["Device"]["Comment"]) or ("FortiGate" in snmpDataDict[snmpHost]["Device"]["FW"])):
			snmpRequest = getCmd (
				SnmpEngine (),
				snmpAuth,
				UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=float(snmpTimeout)),
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
				if verbScanProgressFlag:
					print("\t[WARN!] IP %s [SNMP - Vendor Info] - %s" % (snmpHost, errorIndication))
			elif errorStatus:
				print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
			else:
				# Array for storing SNMP values
				varBindValues = []
				# Extracting SNMP OIDs and their values
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
						snmpDataDict[snmpHost]["Device"][dictKey] = value
	# SNMP GET-NEXT requests payload & processing
	# MAC address obtaining (implemented in interface's physical data collecting bellow)
	# Interface's physical data collecting
	snmpRequest = nextCmd (
		SnmpEngine (),
		snmpAuth,
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=float(snmpTimeout)),
		ContextData (),
		# Interface index @ ifIndex!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifIndex
		ObjectType(ObjectIdentity("IF-MIB", "ifIndex")),
		# Interface description @ ifDescr!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifDescr
		ObjectType(ObjectIdentity("IF-MIB", "ifDescr")),
		# Interface type @ ifType!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifType
		ObjectType(ObjectIdentity("IF-MIB", "ifType")),
		# Interface MTU @ ifMtu!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifMtu
		ObjectType(ObjectIdentity("IF-MIB", "ifMtu")),
		# Interface MAC address @ ifPhysAddress!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifPhysAddress
		ObjectType(ObjectIdentity("IF-MIB", "ifPhysAddress")),
		# Interface administrative status @ ifAdminStatus!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifAdminStatus
		ObjectType(ObjectIdentity("IF-MIB", "ifAdminStatus")),
		# Interface operational status @ ifOperStatus!@#.iso.org.dod.internet.mgmt.mib-2.interfaces.ifTable.ifEntry.ifOperStatus
		ObjectType(ObjectIdentity("IF-MIB", "ifOperStatus")),
		# Interface name @ ifName!@#.iso.org.dod.internet.mgmt.mib-2.ifMIB.ifMIBObjects.ifXTable.ifXEntry.ifName
		ObjectType(ObjectIdentity("IF-MIB", "ifName")),
		# Interface alias @ ifAlias!@#.iso.org.dod.internet.mgmt.mib-2.ifMIB.ifMIBObjects.ifXTable.ifXEntry.ifAlias
		ObjectType(ObjectIdentity("IF-MIB", "ifAlias")),
		lookupMib = True,
		lexicographicMode = False
	)
	snmpIterCount = 0
	while(snmpIterCount < snmpIterMaxCount):
		try:
			errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
			if errorIndication:
				if verbScanProgressFlag:
					print("\t[WARN!] IP %s [SNMP - Interfaces] - %s" % (snmpHost, errorIndication))
			elif errorStatus:
				print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
			else:
				# Extracting SNMP OIDs and their values
				intNumber = None
				for varBind in varBinds:
					### DEBUG: Pretty output of SNMP library
					# print(" = ".join([x.prettyPrint() for x in varBind]))
					name, value = varBind
					# Storing interface index number
					if isinstance(value, Integer32) and ("ifIndex" in name.prettyPrint()):
						intNumber = int(value)
						if intNumber not in snmpDataDict[snmpHost]["Network"].keys():
							snmpDataDict[snmpHost]["Network"].update({intNumber : deepcopy(intDictTempl)})
					# Storing interface data
					# Interface description
					if isinstance(value, OctetString) and ("ifDescr" in name.prettyPrint()) and (len(value) > 0):
						snmpDataDict[snmpHost]["Network"][intNumber]["Description"] = str(value)
					# Interface type
					if isinstance(value, Integer32) and ("ifType" in name.prettyPrint()):
						snmpDataDict[snmpHost]["Network"][intNumber]["Type"] = value.prettyPrint()
					# Interface MTU
					if isinstance(value, Integer32) and ("ifMtu" in name.prettyPrint()):
						snmpDataDict[snmpHost]["Network"][intNumber]["MTU"] = value.prettyPrint()
					# Interface MAC address
					if isinstance(value, OctetString) and ("ifPhysAddress" in name.prettyPrint()) and (len(value) > 0):
						macAddress = str(macaddress.MAC(bytes(value))).replace("-", ":").lower()
						snmpDataDict[snmpHost]["Network"][intNumber]["MAC Address"] = macAddress
						# Collecting MAC address of the device (first interface)
						if intNumber == 1:
							snmpDataDict[snmpHost]["Device"]["MAC Address"] = macAddress
					# Interface administrative status
					if isinstance(value, Integer32) and ("ifAdminStatus" in name.prettyPrint()):
						snmpDataDict[snmpHost]["Network"][intNumber]["Admin Status"] = value.prettyPrint()
					# Interface operational status
					if isinstance(value, Integer32) and ("ifOperStatus" in name.prettyPrint()):
						snmpDataDict[snmpHost]["Network"][intNumber]["Operation Status"] = value.prettyPrint()
					# Interface name
					if isinstance(value, OctetString) and ("ifName" in name.prettyPrint()) and (len(value) > 0):
						intNumber = int(name.prettyPrint().split(".", 1)[1])
						snmpDataDict[snmpHost]["Network"][intNumber]["Name"] = str(value)
					# Interface alias
					if isinstance(value, OctetString) and ("ifAlias" in name.prettyPrint()) and (len(value) > 0):
						intNumber = int(name.prettyPrint().split(".", 1)[1])
						snmpDataDict[snmpHost]["Network"][intNumber]["Alias"] = str(value)
					### DEBUG: OID and its value output
					# print("\tOID = %s" % name)
					# print("\tValue = %s" % value)
			snmpIterCount += 1
		except StopIteration:
			break
	# IP addresses collecting (implemented in interface's logical data collecting bellow)
	# Interface's logical data collecting
	snmpRequest = nextCmd (
		SnmpEngine (),
		snmpAuth,
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=float(snmpTimeout)),
		ContextData (),
		# IP interface index @ ipAdEntIfIndex!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable.ipAddrEntry.ipAdEntIfIndex
		ObjectType(ObjectIdentity("IP-MIB", "ipAdEntIfIndex")),
		# IP interface address @ ipAdEntAddr!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable.ipAddrEntry.ipAdEntAddr
		ObjectType(ObjectIdentity("IP-MIB", "ipAdEntAddr")),
		# IP interface netmask @ ipAdEntNetMask!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipAddrTable.ipAddrEntry.ipAdEntNetMask
		ObjectType(ObjectIdentity("IP-MIB", "ipAdEntNetMask")),
		lookupMib = True,
		lexicographicMode = False
	)
	snmpIterCount = 0
	while(snmpIterCount < snmpIterMaxCount):
		try:
			errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
			if errorIndication:
				if verbScanProgressFlag:
					print("\t[WARN!] IP %s [SNMP - IP Addresses] - %s" % (snmpHost, errorIndication))
			elif errorStatus:
				print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
			else:
				# Extracting SNMP OIDs and their values
				intNumber = None
				for varBind in varBinds:
					### DEBUG: Pretty output of SNMP library
					# print(" = ".join([x.prettyPrint() for x in varBind]))
					name, value = varBind
					# Storing interface index number
					if isinstance(value, Integer32) and ("ipAdEntIfIndex" in name.prettyPrint()):
						intNumber = int(value)
						if intNumber not in snmpDataDict[snmpHost]["Network"].keys():
							snmpDataDict[snmpHost]["Network"].update({intNumber : deepcopy(intDictTempl)})
							snmpDataDict[snmpHost]["Network"][intNumber]["Index"] = intNumber
					# Storing interface address and network mask
					elif isinstance(value, IpAddress):
						ipAddressObject = IPv4Address(value.asOctets())
						objType = "Netmask" if IPAddress(str(ipAddressObject)).is_netmask() else "IP Address"
						snmpDataDict[snmpHost]["Network"][intNumber][objType] = ipAddressObject if (intNumber != None) else None
						if objType == "Netmask":
							snmpDataDict[snmpHost]["Network"][intNumber]["CIDR"] = str(IPv4Network((0, str(ipAddressObject))).prefixlen) if (intNumber != None) else None
					### DEBUG: OID and IP value output
					# print("\tOID = %s" % name)
					# print("\tIP = %s" % IPv4Address(value.asOctets()))
				# Storing an IP address with network mask in CIDR notation
				snmpDataDict[snmpHost]["Device"]["IP Addresses"].append(str(snmpDataDict[snmpHost]["Network"][intNumber]["IP Address"]) + "/" + str(IPv4Network((0, str(snmpDataDict[snmpHost]["Network"][intNumber]["Netmask"]))).prefixlen))
			snmpIterCount += 1
		except StopIteration:
			break
	# Connected routes data collecting
	snmpRequest = nextCmd (
		SnmpEngine (),
		snmpAuth,
		UdpTransportTarget ((snmpHost, snmpPort), retries=snmpRetriesCount, timeout=float(snmpTimeout)),
		ContextData (),
		# Route interface index @ ipRouteIfIndex!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipRouteTable.ipRouteEntry.ipRouteIfIndex
		ObjectType(ObjectIdentity("RFC1213-MIB", "ipRouteIfIndex")),
		# Route type @ ipRouteType!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipRouteTable.ipRouteEntry.ipRouteType
		ObjectType(ObjectIdentity("RFC1213-MIB", "ipRouteType")),
		# Route destination @ ipRouteDest!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipRouteTable.ipRouteEntry.ipRouteDest
		ObjectType(ObjectIdentity("RFC1213-MIB", "ipRouteDest")),
		# Route netmask @ ipRouteMask!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipRouteTable.ipRouteEntry.ipRouteMask
		ObjectType(ObjectIdentity("RFC1213-MIB", "ipRouteMask")),
		# Route next hop (gateway) @ ipRouteNextHop!@#.iso.org.dod.internet.mgmt.mib-2.ip.ipRouteTable.ipRouteEntry.ipRouteNextHop
		# ObjectType(ObjectIdentity("RFC1213-MIB", "ipRouteNextHop")),
		lookupMib = True,
		lexicographicMode = False
	)
	snmpIterCount = 0
	while(snmpIterCount < snmpIterMaxCount):
		try:
			errorIndication, errorStatus, errorIndex, varBinds = next(snmpRequest)
			if errorIndication:
				if verbScanProgressFlag:
					print("\t[WARN!] IP %s [SNMP - IP Routes] - %s" % (snmpHost, errorIndication))
			elif errorStatus:
				print("\t[ERROR!] %s at %s" % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?"))
			else:
				# Extracting SNMP OIDs and their values
				intNumber = None
				routeType = None
				for varBind in varBinds:
					### DEBUG: Pretty output of SNMP library
					# print(" = ".join([x.prettyPrint() for x in varBind]))
					name, value = varBind
					# Storing interface index number
					if isinstance(value, Integer32) and ("ipRouteIfIndex" in name.prettyPrint()):
						intNumber = int(value)
						if intNumber not in snmpDataDict[snmpHost]["Network"].keys():
							snmpDataDict[snmpHost]["Network"].update({intNumber : deepcopy(intDictTempl)})
							snmpDataDict[snmpHost]["Network"][intNumber]["Index"] = intNumber
					# Storing route data
					# Route type
					if isinstance(value, Integer32) and ("ipRouteType" in name.prettyPrint()):
						routeType = value.prettyPrint()
					# Filtering only directly connected networks by route type
					if routeType == "direct":
						if isinstance(value, IpAddress):
							ipAddressObject = IPv4Address(value.asOctets())
							if "ipRouteDest" in name.prettyPrint():
								snmpDataDict[snmpHost]["Network"][intNumber]["Route Network"] = ipAddressObject if (intNumber != None) else None
							if IPAddress(str(ipAddressObject)).is_netmask() and "ipRouteMask" in name.prettyPrint():
								snmpDataDict[snmpHost]["Network"][intNumber]["Route Mask"] = ipAddressObject if (intNumber != None) else None
								snmpDataDict[snmpHost]["Network"][intNumber]["Route CIDR"] = str(IPv4Network((0, str(ipAddressObject))).prefixlen) if (intNumber != None) else None
					### DEBUG: OID and IP value output
					# print("\tOID = %s" % name)
					# print("\tIP = %s" % IPv4Address(value.asOctets()))
			snmpIterCount += 1
		except StopIteration:
			break
	# Filling-ip IP address with None if there are no any addresses
	if len(snmpDataDict[snmpHost]["Device"]["IP Addresses"]) == 0:
		snmpDataDict[snmpHost]["Device"]["IP Addresses"] = None
	else:
		# Flipping SNMP state flag
		snmpDataDict[snmpHost]["Device"]["SNMP"] = True
	### DEBUG
	# Inventory dictionary output
	# print("\n\nInventory dictionary:")
	# print(snmpDataDict)
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
def generateCSVReport(inputDict, netAddress, templateDict, reportType, csvDelimeter=",", emptyValue="N/A"):
	# Processing data
	reportContent = ""
	### HEADER DATA
	if ((templateDict != None) and isinstance(templateDict, dict) and (len(templateDict)) > 0):
		# Generating header row
		match reportType:
			case "Network": csvFileHeader = ["Sysname", "S/N"]
			case _: csvFileHeader = ["Network", "Host"]
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
			csvRowPrefix = ""
			match reportType:
				case "Network":
					devSysname = inputDict[host]["Device"]["Sysname"]
					devSysname = devSysname if devSysname != None else emptyValue
					devSerialNumber = inputDict[host]["Device"]["S/N"]
					devSerialNumber = devSerialNumber if devSerialNumber != None else emptyValue
					csvRowPrefix = (devSysname + csvDelimeter) + (devSerialNumber + csvDelimeter)
				case _: csvRowPrefix = (netAddress + csvDelimeter) + (host + csvDelimeter)
			# Processing multiple values from dictionary
			if reportType == "Network":
				# Processing network inventory dictionary
				for element in inputDict[host][reportType]:
					csvRowData += csvRowPrefix
					for subelement in inputDict[host][reportType][element]:
					# Processing any non-zero values
						if subelement != None:
							elementValue = str(inputDict[host][reportType][element][subelement])
						# None-values processing
						else:
							elementValue = emptyValue
						csvRowData += elementValue + csvDelimeter
					csvRowData = csvRowData.removesuffix(csvDelimeter)
					csvRowData += "\n"
			else:
				# Processing device inventory dictionary
				csvRowData += csvRowPrefix
				for element in inputDict[host][reportType]:
					# Processing multiple IP addresses values
					if (element == "IP Addresses" and isinstance(inputDict[host][reportType][element], list)):
						elementValue = ""
						for ipAddress in inputDict[host][reportType][element]:
							elementValue += ipAddress + ", "
						elementValue = elementValue.removesuffix(", ")
					# Processing any non-zero values
					elif element != None:
						elementValue = str(inputDict[host][reportType][element])
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
		print("Nothing to flush to the file!")
		sys.exit()		
	else:
		try:
			print("Flushing data to the file \"%s\"..." % filePath)
			file = open(filePath, "w+", encoding="utf8")
			file.writelines(memContent)
			file.close()
		except:
			print("Failed to flush to the output file!")
			sys.exit()

### Main code block
# Determinating the time of start	
startTime = time.time()
print("\nNetSNMP Inventory Tool v" + __version__ + " by " + __author__ + ".")

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
	netScanDict[netDescription].update({str(hostAddress) : deepcopy(templatesDict["Summary"])})
else:
	for hostAddress in scanAddress:
		if ((hostAddress != netAddress) and (hostAddress != netBroadcastAddress)):
			netScanDict[netDescription].update({str(hostAddress) : deepcopy(templatesDict["Summary"])})

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
	netScanDict[netDescription][hostAddress]["Device"]["PING"] = hostIsActive
	# Performing SNMP host audit
	if hostIsActive or ignorePingFlag:
		print("\tProgress: IP %s [SNMP] - %d of %d (%.2f%%)" % (hostAddress, currentAddressNumber, netAddressesCount, currentAddressNumber/netAddressesCount*100), end="\r")
		netScanDict[netDescription].update(snmpAudit(hostAddress, hostIsActive, snmpUsername, snmpAuthKey, snmpPrivKey, templatesDict["Summary"], templatesDict["Network"], csvReportDelimeter, snmpAuthProtocol, snmpPrivProtocol, snmpPort, snmpIterMaxCount, snmpRetriesCount, snmpTimeout))
	# Incrementing address number
	currentAddressNumber += 1

# Printing out the results
if scanResultsOutputFlag:
	print("\n\nThe scan results for network %s are:" % (netDescription))
	for hostAddress in netScanDict[netDescription]:
		resultString = "\t " + hostAddress + ": "
		for element in netScanDict[netDescription][hostAddress]["Device"]:
			# Processing multiple IP addresses values
			if (element == "IP Addresses" and isinstance(netScanDict[netDescription][hostAddress]["Device"][element], list)):
				elementValue = ""
				# IP addresses arrays
				for ipAddress in netScanDict[netDescription][hostAddress]["Device"][element]:
					elementValue += ipAddress + ", "
				elementValue = elementValue.removesuffix(", ")
			# Any non-zero values
			elif netScanDict[netDescription][hostAddress]["Device"][element] != None:
				elementValue = str(netScanDict[netDescription][hostAddress]["Device"][element])
			# None-values
			else:
				elementValue = reportEmptyValue
			resultString = resultString + element + " = " + elementValue + "; "
		print(resultString.removesuffix(" "))

# Determinating the time of end
endTime = time.time()

# Statistic printing and exiting
if not scanResultsOutputFlag:
	print()
print("\n%d hosts have been scanned in %s." % (netAddressesCount, convertTime(endTime-startTime)))
print()

# Generating CSV file content & flushing data into file
for key in templatesDict:
	if key != "Summary":
		# Filling-up content
		outFileContent = generateCSVReport(netScanDict[netDescription], netDescription, templatesDict[key], key, csvReportDelimeter, reportEmptyValue)
		### DEBUG: CSV report printing
		# print("Results output in CSV format:")
		# print(outFileContent)
		# Flushing data into file
		print("Exporting %ss report into CSV file..." % key.lower())
		# Generating full path to report file
		outFilePath = outDirPath + (datetime.today().strftime("%Y-%m-%d") + " – net-audit-report_" + key.lower() + "s_net-" + str(scanAddress).replace("/", "_cidr-") + ".csv") 
		flushMemContentToFile(outFilePath, outFileContent)

print("\nDone!\n")

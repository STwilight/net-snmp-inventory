#!/usr/bin/python3

import pyinstaller_versionfile

# Generating version file for PyInstaller tool
pyinstaller_versionfile.create_versionfile(
    output_file = "version-info.txt",
    version = "0.2.3",
    company_name = "Symrak",
    file_description = "Utility for network equipment discovery & audit",
    internal_name = "NetSNMP Inventory Tool",
	legal_copyright = "Symrak",
    original_filename = "net-snmp-inventory.exe",
    product_name = "NetSNMP Inventory Tool"
)
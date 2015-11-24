"""
WinWAP.py
Forensics by James
Date: 20151123
Searches history of wireless access points in the Windows Registry
"""
from _winreg import *

#__________________________________________________________
#converts REG_BINARY to an readable MAC address            |
#ie \x00\x11\x50\x24\x68\x7F\x00\x00 to 00:11:50:24:68:7F  |
#----------------------------------------------------------

def val2addr(val):
	addr = ""
	for ch in val:
		addr += ("%02x "% ord(ch))
	addr = addr.strip(" ").replace(" ",":")[0:17]
	return addr
#___________________________________________________________
# Extracts the network name and MAC address for ea profile  |
# uses winreg library installed by Windows Python INstaller |
# openKey() loops through net. profiles and subkeys:        |
#ProfileGuid, Description, Source, DnsSuffix, FirstNetwork  |
#DefaultGatewayMac.                                         |
#-----------------------------------------------------------


def printNets():
	net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"+\
	"\NetworkList\Signatures\Unmanaged"
key = OpenKey(HKEY_LOCAL_MACHINE, net)
print '\n[*] Networks You have Joined.'
for i in range (100):
	try:
		guid = EnumKey(key, i)
		netKey = OpenKey(key, str(guid))
		(n, addr, t) = EnumValue(netKey, 5)
		(n, name, t) = EnumValue(netKey, 4)
		macAddr = val2addr(addr)
		netName = str(name)
		print '[+]'+netName+' '+macAddr
		CloseKey(netKey)
	except:
		break
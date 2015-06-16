#!/usr/bin/python

# Much credit is due to the SRX Session Analyzer written by Tim Eberhard which helped me get started on this program


import sys
import re

#Command line arguments:  (COMING SOON!!)
# -s source			
# -d destination		
# -p port			
# -D deny			
# -P permit			
# -C close			
# -z zone			
# -i interface		
# -n policy name

#Basic stuff to use for later. This is static and should never change.
protocolnum = {0:" HOPOPT ", 1: "ICMP", 2: "IGMP", 3: "GGP ", 4: "IP ", 5: "ST ", 6: "TCP ", 7: "CBT ", 8: "EGP ", 9: "IGP ", 10: "BBN-RCC-MON ", 11: "NVP-II ", 12: "PUP ", \
13: "ARGUS ", 14: "EMCON ", 15: "XNET ", 16: "CHAOS ", 17: "UDP ", 18: "MUX ", 19: "DCN-MEAS ", 20: "HMP ", 21: "PRM ", 22: "XNS-IDP ", 23: "TRUNK-1 ", 24: "TRUNK-2 ", \
25: "LEAF-1 ", 26: "LEAF-2 ", 27: "RDP ", 28: "IRTP ", 29: "ISO-TP4 ", 30: "NETBLT ", 31: "MFE-NSP ", 32: "MERIT-INP ", 33: "DCCP ", 34: "3PC ", 35: "IDPR ", 36: "XTP ", \
37: "DDP ", 38: "IDPR-CMTP ", 39: "TP++ ", 40: "IL ", 41: "IPv6 ", 42: "SDRP ", 43: "IPv6-Route ", 44: "IPv6-Frag ", 45: "IDRP ", 46: "RSVP ", 47: "GRE ", 48: "DSR ", \
49: "BNA ", 50: "ESP ", 51: "AH ", 52: "I-NLSP ", 53: "SWIPE ", 54: "NARP ", 55: "MOBILE ", 56: "TLSP ", 57: "SKIP ", 58: "IPv6-ICMP ", 59: "IPv6-NoNxt ", 60: "IPv6-Opts ", \
61: "any ", 62: "CFTP ", 63: "any ", 64: "SAT-EXPAK ", 65: "KRYPTOLAN ", 66: "RVD ", 67: "IPPC ", 68: "any ", 69: "SAT-MON ", 70: "VISA ", 71: "IPCV ", 72: "CPNX ", \
73: "CPHB ", 74: "WSN ", 75: "PVP ", 76: "BR-SAT-MON ", 77: "SUN-ND ", 78: "WB-MON ", 79: "WB-EXPAK ", 80: "ISO-IP ", 81: "VMTP ", 82: "SECURE-VMTP ", 83: "VINES ", \
84: "TTP ", 85: "NSFNET-IGP ", 86: "DGP ", 87: "TCF ", 88: "EIGRP ", 89: "OSPFIGP ", 90: "Sprite-RPC ", 91: "LARP ", 92: "MTP ", 93: "AX.25 ", 94: "IPIP ", 95: "MICP ", \
96: "SCC-SP ", 97: "ETHERIP ", 98: "ENCAP ", 99: "any ", 100: "GMTP ", 101: "IFMP ", 102: "PNNI ", 103: "PIM ", 104: "ARIS ", 105: "SCPS ", 106: "QNX ", 107: "A/N ", \
108: "IPComp ", 109: "SNP ", 110: "Compaq-Peer ", 111: "IPX-in-IP ", 112: "VRRP ", 113: "PGM ", 114: "any ", 115: "L2TP ", 116: "DDX ", 117: "IATP ", 118: "STP ", \
119: "SRP ", 120: "UTI ", 121: "SMP ", 122: "SM ", 123: "PTP ", 124: "ISIS over IPv4 ", 125: "FIRE ", 126: "CRTP ", 127: "CRUDP ", 128: "SSCOPMCE ", 129: "IPLT ", \
130: "SPS ", 131: "PIPE ", 132: "SCTP ", 133: "FC ", 134: "RSVP-E2E-IGNORE ", 135: "Mobility Header  ", 136: "UDPLite ", 137: "MPLS-in-IP ", \
138-252: "Unassigned ", 253: "Use for experimentation and testing ", 254: "Use for experimentation and testing ", 255: "Reserved"}



def parsestring(line):
	try:	
		# Session creation log entries	
		if "session created" in line: 
			action = "permit"	
			##Split's the IP's into a source group and a destination group	
			ipheader = line.split("created")[1].split()[0].replace("->"," ").split()
			src, dest = ipheader[0:]
		
			#Takes Destination and seperates IP from port
			srcip, srcport = src.split("/")
			destip,destport = dest.split("/")
			
			#Get zone and interface info
			sessioninfo = line.split("->")[2].split()
			srczone = sessioninfo[5]
			dstzone = sessioninfo[6]
			interface = sessioninfo[9]
			protocol = protocolnum.get(int(sessioninfo[3]))
			policyname = sessioninfo[4]
			
			logentry = [action, srcip, destip, destport, protocol, srczone, dstzone, interface, policyname]
			printlog(logentry)
		
		if "session denied" in line: 
			action = "denied"	
			##Split's the IP's into a source group and a destination group	
			ipheader = line.split("denied")[1].split()[0].replace("->"," ").split()
			src, dest = ipheader[0:]
		
			#Takes Destination and seperates IP from port
			srcip, srcport = src.split("/")
			destip,destport = dest.split("/")
			
			#Get zone and interface info
			sessioninfo = line.split("denied")[1].split()
			srczone = sessioninfo[4]
			dstzone = sessioninfo[5]
			
			#Junos will truncate messages using the sd-syslog format so sometimes the full interface name is lost
			interface = sessioninfo[9]
			protocol = protocolnum.get(int(sessioninfo[2].split("(")[0]))
			policyname = sessioninfo[4]
			
			logentry = [action, srcip, destip, destport, protocol, srczone, dstzone, interface, policyname]
			printlog(logentry)
			
		if "session closed" in line: 
			action = line.split("closed")[1].split(":")[0].lstrip()
			##Split's the IP's into a source group and a destination group	
			ipheader = line.split("closed")[1].split()[2].replace("->"," ").split()
			src, dest = ipheader[0:]
		
			#Takes Destination and seperates IP from port
			srcip, srcport = src.split("/")
			destip,destport = dest.split("/")
			
			#Get zone and interface info
			sessioninfo = line.split("->")[2].split()
			srczone = sessioninfo[5]
			dstzone = sessioninfo[6]
			interface = sessioninfo[14]
			protocol = protocolnum.get(int(sessioninfo[3]))
			policyname = sessioninfo[4]
			
			logentry = [action, srcip, destip, destport, protocol, srczone, dstzone, interface, policyname]
			printlog(logentry)

	except:pass

def printlog(log):
	#print "{0:7} {1:16} {2:16} {3:7} {4:3} {5:20} {6:20} {7:18} {8}".format(action, srcip, destip, destport, protocol, srczone, dstzone, interface, policyname)
	print "{0:19} {1:16} {2:16} {3:7} {4:5} {5:20} {6:20} {7:18} {8}".format(log[0], log[1], log[2], log[3], log[4], log[5], log[6], log[7], log[8])

try:
	for line in sys.stdin:
		parsestring(line)	
except (KeyboardInterrupt, SystemExit):
	sys.exit()


#!/usr/bin/env python
import os
import sys
import getopt
from parserfiles import ParserFiles, main
from subprocess import Popen, PIPE


sep = ' '

class AccessPoint(object):
	mac = []
	bssid = []
	ssid = ""

	def __init__(self, mac, ssid):
		self.mac = mac
		self.ssid = ssid

	def show_info(self):
		print ""
		print "AP mac [%s]" % self.mac
		print "AP ssid[%s]" % self.ssid

	def get_mac(self):
		return self.mac

class Station(object):
	mac = ""

	def __init__(self, mac):
		self.mac = mac

	def show_info(self):
		print ""
		print "STA mac [%s]" % self.mac

	def get_mac(self):
		return self.mac


def get_access_points(pfiles):
	bcn_flr = "wlan.fc.type_subtype == 8"

	tshark_cmd = []
	tshark_cmd.append("tshark")
	tshark_cmd.append("-r%s" % pfiles.get_input_path())
	tshark_cmd.append("-Y%s" % bcn_flr)
	tshark_cmd.append("-Tfields")
	tshark_cmd.append("-Eheader=y")
	tshark_cmd.append("-Eseparator=" + sep)
	tshark_cmd.append("-ewlan.sa")
	tshark_cmd.append("-ewlan_mgt.ssid")
	#tshark_cmd.append("-wmoni-1_filtered.pcap")

	#print tshark_cmd
	# filter raw pcap file
	process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
	(result, error_msg) = process.communicate()
	if error_msg:
		print "ERROR:"
		print error_msg
		
	lines = result.splitlines()

	ap_list = []
	for i in range(1, len(lines)):
		line = lines[i]
		(macaddr, ssid) = line.split(sep, 1)
		ap_exist = False
		for ap in ap_list: 
			if macaddr == ap.get_mac():
				ap_exist = True
		if not ap_exist:
			ap_list.append(AccessPoint(macaddr, ssid))
		
	return ap_list

def get_stas(pfile):
	sta_list = []

	prbreq_flr = "wlan.fc.type_subtype == 4"

	tshark_cmd = []
	tshark_cmd.append("tshark")
	tshark_cmd.append("-r%s" % pfiles.get_input_path())
	tshark_cmd.append("-Y%s" % prbreq_flr)
	tshark_cmd.append("-Tfields")
	tshark_cmd.append("-Eheader=y")
	tshark_cmd.append("-Eseparator=" + sep)
	tshark_cmd.append("-ewlan.sa")
	#tshark_cmd.append("-wmoni-1_filtered.pcap")

	#print tshark_cmd
	# filter raw pcap file
	process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
	(result, error_msg) = process.communicate()
	if error_msg:
		print "ERROR:"
		print error_msg
		
	lines = result.splitlines()

	sta_set = set(lines[1:])
	for sta in sta_set:
		sta_list.append(Station(sta))
		
	return sta_list


##################################################
if __name__ == "__main__":
	pfiles = main(sys.argv[1:])
	ap_list = get_access_points(pfiles)
	sta_list = get_stas(pfiles)

	# print info for all found APs
	for ap in ap_list:
		ap.show_info()

	for sta in sta_list:
		sta.show_info()




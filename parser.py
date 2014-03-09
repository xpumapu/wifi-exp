#!/usr/bin/env python
import os
import sys
import getopt
from subprocess import Popen, PIPE

sep = ' '

class ParserFiles(object):
	in_file = ""
	out_file = ""
	log_file = ""
	cwd_path = ""
	in_path = ""
	out_path = ""

	def __init__(self, infile):
		self.in_file = os.path.basename(infile)
		self.cwd_path = os.getcwd()
		if os.path.isabs(infile):
			self.in_path = infile
		else :
			self.in_path = os.path.normpath(os.path.join(self.cwd_path, infile))
		if not os.path.exists(self.in_path):
			print "ParserFiles error: input file does not exist " + self.in_path

	def set_output_file(self, outfile):
		self.out_file = os.path.basename(outfile)
		if os.path.isabs(outfile):
			self.out_path = outfile
		else :
			self.out_path = os.path.normpath(os.path.join(self.cwd_path, outfile))

	def get_input_path(self):
		return self.in_path

	def get_output_path(self):
		return self.out_path

	def show_info(self):
		print ""
		print "ParserFiles input file [%s]" % self.in_path
		print "ParserFiles output file [%s]" % self.out_path


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

def main(argv):
	inputfile = ''
	outputfile = ''
	try:
		(opts, args) = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
	except getopt.GetoptError:
		print os.path.basename(__file__) + " -i <inputfile> -o <outputfile"
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print os.path.basename(__file__) + " -i <inputfile> -o <outputfile"
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-o", "--ofile"):
			outputfile = arg

	pfiles = ParserFiles(inputfile)
	pfiles.set_output_file(outputfile)
	pfiles.show_info()

	return pfiles


def get_access_points(pfiles):
	bcn_flr = "wlan.fc.type_subtype == 8"

	tshark_cmd = []
	tshark_cmd.append("tshark")
	tshark_cmd.append("-r%s" % pfiles.get_input_path())
	tshark_cmd.append("-R%s" % bcn_flr)
	tshark_cmd.append("-Tfields")
	tshark_cmd.append("-Eheader=y")
	tshark_cmd.append("-Eseparator=" + sep)
	tshark_cmd.append("-eframe.number")
	tshark_cmd.append("-ewlan.sa")
	tshark_cmd.append("-ewlan_mgt.ssid")
	#tshark_cmd.append("-wmoni-1_filtered.pcap")

	#print tshark_cmd
	# filter raw pcap file
	process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
	(result, notused) = process.communicate()
	#print result
	lines = result.splitlines()
	ap_list = []
	for i in range(1, len(lines)):
		line = lines[i]
		(nr, macaddr, ssid) = line.split(sep, 2)
		ap_exist = False
		for ap in ap_list: 
			if macaddr == ap.get_mac():
				ap_exist = True
		if not ap_exist:
			ap_list.append(AccessPoint(macaddr, ssid))
		
	return ap_list

def filter_data(pfiles, src_mac, dst_mac):
	data_flr = "wlan.fc.type_subtype == 0x28"
	src_flr = "wlan.sa == " + src_mac
	dst_flr = "wlan.da == " + dst_mac
	flr = data_flr + " and " + src_flr + " and " + dst_flr

	tshark_cmd = []
	tshark_cmd.append("tshark")
	tshark_cmd.append("-r%s" % pfiles.get_input_path())
	tshark_cmd.append("-R%s" % data_flr)
	#tshark_cmd.append("-R%s" % src_flr)
	#tshark_cmd.append("-R%s" % dst_flr)
	tshark_cmd.append("-Tfields")
	tshark_cmd.append("-Eheader=y")
	tshark_cmd.append("-Eseparator=" + sep)
	tshark_cmd.append("-eframe.number")
	tshark_cmd.append("-ewlan.sa")
	tshark_cmd.append("-ewlan.da")
	tshark_cmd.append("-edata.len")
	#tshark_cmd.append("-wmoni-1_filtered.pcap")

	print tshark_cmd
	# filter raw pcap file
	process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
        (result, notused) = process.communicate()
	return result

#######################
scr_mac = "00:24:14:54:92:00"
dst_mac = "00:26:bb:12:ff:32"

if __name__ == "__main__":
	pfiles = main(sys.argv[1:])
	print "p1"
	ap_list = get_access_points(pfiles)

	# print info for all found APs
	for ap in ap_list:
		ap.show_info()

	nr_data = filter_data(pfiles, scr_mac, dst_mac)
	print ""
	print nr_data




# parse results from air logs
# filter raw air logs, only ap and client packets can stay
def func():
	flr1 = "wlan.addr==%s" % client_mac
	flr2 = "wlan.addr==%s" % ap_mac
	tshark_cmd = "tshark -r%s -R%s -R%s -w%s" % (sniffer_raw_file, flr1, flr2, sniffer_filtered_file)
	status, buf = sniffer.execute(tshark_cmd)
	if status != 0:
		raise Exception("Tshark failed: (%s) %s" % (status, buf))
	# leave only data frames and take only interestin information
	flr3 = "wlan.fc.type_subtype==0x28"	
	tshark_cmd = "tshark -r%s -R%s -T fields -E header=y -E separator='^' -e frame.number -e wlan.sa -e wlan.da -e wlan.wep.key" % (sniffer_filtered_file, flr3) 
	status, buf = sniffer.execute(tshark_cmd)
	if status != 0:
		raise Exception("Tshark failed: (%s) %s" % (status, buf))

	sbuf = buf.split('\n')
	sbuf_len = len(sbuf)
	j=0
	packets = {}
	for i in range(sbuf_len):
		if "frame.number" in sbuf[i]:
			j = 1
		if j >= 1:
			packets[j] = sbuf[i].split('^')
	j += 1

	# find ping packets with correct WEP key, first raw is header, start from second raw
	for i in range(2, j):
		(fn, sa, da, wep_key) = packets[i]
		if sa==client_mac and da==ap_mac and int(wep_key)!=int(client_def_key_idx):
			raise Exception("Wrong AP tx WEP key, used %s, set %s " % (wep_key, client_def_key_idx))
		if sa==ap_mac and da==client_mac and int(wep_key)!=int(ap_def_key_idx):
			raise Exception("Wrong STA tx WEP key, used %s, set %s " % (wep_key, ap_def_key_idx))




#!/usr/bin/env python

from subprocess import Popen, PIPE


sniffer_raw_file = "moni0.pcap"

bcn_flr = "wlan.fc.type_subtype == 8"

tshark_cmd = []
tshark_cmd.append("tshark")
tshark_cmd.append("-r%s" % sniffer_raw_file)
tshark_cmd.append("-R%s" % bcn_flr)
tshark_cmd.append("-Tfields")
tshark_cmd.append("-Eheader=y")
tshark_cmd.append("-eframe.number")
tshark_cmd.append("-ewlan.sa")
tshark_cmd.append("")
#tshark_cmd.append("-wmoni-1_filtered.pcap")

print tshark_cmd
process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
(result, notused) = process.communicate()

print result




print "testststst \n \n"


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




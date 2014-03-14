#!/usr/bin/env python
import os
import sys
import getopt
from parserfiles import ParserFiles, main
from subprocess import Popen, PIPE

sep = ' '

def count_factor(pfiles, sta1_mac, sta2_mac, term_mac):
	#RTP3
	data_flr = "wlan.fc.type_subtype == 0x20"
	src_flr = "wlan.sa == " + sta2_mac
	dst_flr = "wlan.da == " + term_mac
	retry_flr = "wlan.fc.retry == 1"
	flr = data_flr + " and " + src_flr + " and " + dst_flr + " and !" + retry_flr

	tshark_cmd = []
	tshark_cmd.append("tshark")
	tshark_cmd.append("-2")
	tshark_cmd.append("-r%s" % pfiles.get_input_path())
	tshark_cmd.append("-R%s" % flr)
	tshark_cmd.append("-Tfields")
	tshark_cmd.append("-Eheader=y")
	tshark_cmd.append("-Eseparator=" + sep)
	tshark_cmd.append("-eframe.number")
	tshark_cmd.append("-edata.len")
	tshark_cmd.append("-eframe.time_relative")
	#tshark_cmd.append("-w%s" % pfiles.get_output_path())

	#print tshark_cmd
	# filter raw pcap file
	process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
        (result, error_msg) = process.communicate()
	if error_msg:
		print "ERROR:"
		print error_msg

	lines = result.splitlines()
	i = int(1)
	(fr_nr, dlen, time) = lines[i].split(' ', 2)
	i += 1
	start_time = float(time) + 1.0
	curr_time = float(0)

	while curr_time < start_time:
		(fr_nr, dlen, time) = lines[i].split(' ', 2)
		i += 1
		curr_time = float(time)

	end_time = float(start_time + 8.0)

	print "start time " + str(start_time)
	print "end time " + str(end_time)
	rtp3_data = int(dlen)

	while curr_time < end_time:
		(fr_nr, dlen, time) = lines[i].split(' ', 2)
		i += 1
		if not dlen:
			print "No data "
			break
		rtp3_data += int(dlen)
		curr_time = float(time)

	
	rtp3_rate = float(rtp3_data) / float(curr_time - start_time)
	rtp3_rate = rtp3_rate / 1024
	print " "
	print "RTP3 rate " + str(rtp3_rate) + " KBps"

	#RTP1
	end_time = curr_time
	qosdata_flr = "wlan.fc.type_subtype == 0x28"
	src_flr = "wlan.sa == " + term_mac
	dst_flr = "wlan.da == " + sta1_mac
	retry_flr = "wlan.fc.retry == 1"
	flr = qosdata_flr + " and " + src_flr + " and " + dst_flr + " and !" + retry_flr

	tshark_cmd = []
	tshark_cmd.append("tshark")
	tshark_cmd.append("-2")
	tshark_cmd.append("-r%s" % pfiles.get_input_path())
	tshark_cmd.append("-R%s" % flr)
	tshark_cmd.append("-Tfields")
	tshark_cmd.append("-Eheader=y")
	tshark_cmd.append("-Eseparator=" + sep)
	tshark_cmd.append("-eframe.number")
	tshark_cmd.append("-edata.len")
	tshark_cmd.append("-eframe.time_relative")
	#tshark_cmd.append("-w%s" % pfiles.get_output_path())

	#print tshark_cmd
	# filter raw pcap file
	result = []
	process = Popen(tshark_cmd, stdout=PIPE, stderr=PIPE)
        (result, error_msg) = process.communicate()
	if error_msg:
		print "ERROR:"
		print error_msg

	lines = result.splitlines()
	i = int(1)
	curr_time = float(0)

	while curr_time < start_time:
		(fr_nr, dlen, time) = lines[i].split(' ', 2)
		i += 1
		curr_time = float(time)

	rtp1_data = int(0)

	while curr_time < end_time:
		(fr_nr, dlen, time) = lines[i].split(' ', 2)
		if not dlen:
			print "No data "
			break
		rtp1_data += int(dlen)
		curr_time = float(time)
		i += 1

	rtp1_rate = float(rtp1_data) / float(curr_time - start_time)
	rtp1_rate = rtp1_rate / 1024
	print " "
	print "RTP1 rate " + str(rtp1_rate) + " KBps"

	rate = float(rtp1_rate / rtp3_rate)

	return rate

#######################
#scr_mac = "00:24:14:54:92:00"
#dst_mac = "00:26:bb:12:ff:32"
# Intel
intel_mac = "24:77:03:3e:00:58"
# Broadcom
brcm_mac = "00:10:18:96:2a:0c"
# APUT
aput_mac = "00:03:7f:48:d0:b5"

# terminal behind APUT
term_mac = "00:26:5a:0f:2b:8f"
# STA1
sta1_mac = brcm_mac
# STA2
sta2_mac = intel_mac


##################################################
if __name__ == "__main__":
	pfiles = main(sys.argv[1:])

	rate = count_factor(pfiles, sta1_mac, sta2_mac, term_mac)
	print ""
	print "Rate factor [" + str(rate) + "]"



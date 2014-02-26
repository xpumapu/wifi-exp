#!/usr/bin/env python
"USAGE: %s ap_name client_name ap_config client_config tc_number"
from RemoteClient import RemoteClient
from RemoteClient import ClientsTable
from RemoteClient import execute_thread
from sys import *
import time
import traceback
import threading
import os


# WEP TC
# tests WEP encryption decryption,

def get_ap_config(ap_config, iface):
	ssid = ""
	psk = ""
	interface = ""
	change_iface = 0
	with open (ap_config, "r") as myfile:
		lines = myfile.readlines()
    
	ap_config_new = ap_config + "_new"
	out_file = open(ap_config_new, "w")
	for line in lines:
		if line[0] == '#':
			continue
		if len(line) <= 1:
			continue
		#print "Checking: ", line, len(line)
		# find interface
		res = cmp(line[:10], "interface=")
		if res == 0:
			interface = line[10:]
			interface = interface[:-1]
			if interface != iface:
				line = "interface=" + iface + "\n"
				change_iface = 1

		# find ssid
		res = cmp(line[:5], "ssid=")
		if res == 0:
			ssid = line[5:]
			ssid = ssid[:-1]

		# find psk
		res = line.find("wpa_passphrase=")
		if res != -1:
			psk = line[15:]
			psk = psk[:-1]

		out_file.write(line)

	return ap_config_new, ssid, psk

def get_ap_wep_config(ap_config, iface):
	ssid = ""
	def_key_index = ""
	wep_keys = ""
	interface = ""
	change_iface = 0
	with open (ap_config, "r") as myfile:
		lines = myfile.readlines()
    
	ap_config_new = ap_config + "_new"
	out_file = open(ap_config_new, "w")
	for line in lines:
		if line[0] == '#':
			continue
		if len(line) <= 1:
			continue
		# find interface
		res = cmp(line[:10], "interface=")
		if res == 0:
			interface = line[10:]
			interface = interface[:-1]
			if interface != iface:
				line = "interface=" + iface + "\n"
				change_iface = 1

		# find ssid
		res = cmp(line[:5], "ssid=")
		if res == 0:
			ssid = line[5:]
			ssid = ssid[:-1]

		# find def key index
		res = cmp(line[:16], "wep_default_key=")
		if res == 0:
			def_key_index = line[16:]
			def_key_index = def_key_index[:-1]

		#find wep keys
		res = cmp(line[:9], "wep_key0=")
		if res == 0:
			wep_keys = line[9:]
			wep_keys = wep_keys[:-1]

		out_file.write(line)

	return ap_config_new, ssid, wep_keys, def_key_index

def get_client_wep_config(config, tc):
	def_key_idx = 0
	network = 0

	with open (config, "r") as myfile:
                lines = myfile.readlines()
	lines_len = len(lines)
	print lines_len

	for i in range(lines_len):
		line = lines[i]
		if line[0] == '#':
                        continue
		res = cmp(line[:8], "network=")
		if res == 0:
			network +=1
		if int(network) == int(tc):
			break

	for j in range(i, lines_len):
		line = lines[j]
		if "wep_tx_keyidx=" in line:
			def_key_idx = int(line[-2])
		res = cmp(line[:1], "}")
		if res == 0:
			break

	return def_key_idx

def tc_wep(tc_name, ap = "ath9k-2", client = "ath9k-1", ap_config_in = "ap.conf", client_config = "wpa_supplicant.conf", tc_index = 1):
	# get client/ap configuration
	table = ClientsTable("ClientsTable.txt")
	vendor1, ip1, iface1 = table.get_client(ap)
	vendor2, ip2, iface2 = table.get_client(client)
	vendor3, ip3, iface3 = table.get_client("sniffer")
	# wifi network
	ap_ip = "192.168.60.1"
	client_ip = "192.168.60.2"

	# get wep config from hostapd conf file
	ap_config, ssid, wep_keys, ap_def_key_idx = get_ap_wep_config(ap_config_in, iface1)
	# get wep config from wpa_supplicant conf file
	client_def_key_idx = get_client_wep_config(client_config, tc_index)

	ap_log_file = ap + "_" + tc_name + ".log"
	client_log_file = client + "_" + tc_name + ".log"
	sniffer_raw_file = tc_name + "_raw.pcap"
	sniffer_filtered_file = tc_name + "_filtered.pcap"

	try:
		client1 = RemoteClient(ip1)
		client2 = RemoteClient(ip2)
		sniffer = RemoteClient(ip3)

		ap_mac = client1.get_iface_mac(iface1)
		client_mac = client2.get_iface_mac(iface2)

		print "======================================================="
		print tc_name
		print " - using AP: ", ap, " if:", iface1," IP:", ip1, " wifi:", ap_ip, " mac:", ap_mac
		print " - using STA: ", client, " if:", iface2, " IP:", ip2, " wifi:", client_ip, " mac:", client_mac
		print " - sniffer if:", iface3, " IP:", ip3
		print " - using ap config: ", ap_config
		print " - using sta config: ", client_config
		print " - ssid: ", ssid
		print " - wep keys: ", wep_keys
		print " - ap def wep key: ", ap_def_key_idx
		print " - client tx wep key: ", client_def_key_idx
		print "======================================================="

		# run hostapd
		client1.execute("killall wpa_supplicant")
		client1.execute("killall hostapd")
		time.sleep(2)
		client1.execute("rm -f " + ap_log_file)
		status, buf = client1.local_execute("scp %s root@%s:" % (ap_config, client1.ip))
		if status != 0:
			raise Exception(ap_config)

		client1.execute("./hostapd -ddtK -f %s -B %s" % (ap_log_file, ap_config))
		client1.execute("ifconfig %s %s" % (iface1, ap_ip))
		# remove client IP from ARP table in order to test multicast data transfer
		client1.execute("arp -d " + client_ip)

		# run supplicant
		client2.execute("killall wpa_supplicant")
		client2.execute("killall hostapd")
		time.sleep(1)
		status, buf = client2.local_execute("scp %s root@%s:" % (client_config, client2.ip));
		if status != 0:
			raise Exception("Client config %s copy failed" % client_config)

		status, buf = client2.execute("./wpa_supplicant -Dnl80211 -i %s -ddt -f %s -B -c %s" % (iface2, client_log_file, client_config))
		if status != 0:
			raise Exception("Client start supplicant failed: %s" % status)

		client2.execute("ifconfig %s %s" % (iface2, client_ip))
		# remove AP IP from ARP table
		client2.execute("arp -d " + ap_ip)

		# connect remote wpa_cli
		client2.connect_wpa_cli(iface2)

		# start snifer
		# delete old sniffer logs
		sniffer.execute("rm -rfv %s" % sniffer_raw_file)
		sniffer.execute("rm -rfv %s" % sniffer_filtered_file)
		# start loging all packets on monitor to file
		t = sniffer.start_sniffer(iface3, sniffer_raw_file)

		# enable network corresponding to tc number
		client2.send_simple("ENABLE_NETWORK " + str(int(tc_index)-1))
		client2.wait_msg("CTRL-EVENT-CONNECTED", 30)

		# some traffic in both directions to test connection
		status, buf = client2.execute("ping -n -c3 %s" % ap_ip)
		if status != 0:
			raise Exception("Ping to AP failed: (%s) %s" % (status, buf))

		status, buf = client1.execute("ping -n -c3 " + client_ip)
		if status != 0:
			raise Exception("Ping to client failed: (%s) %s" % (status, buf))

		# stop sniffer
		sniffer.stop_sniffer()

		# parse results from air logs
		# filter raw air logs, only ap and client packets can stay
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

		# format TC RESULT
		append_to_tc_result = client + " connection to " + ap + " works\n"

		print "======================================================="
		print "TC RESULT - " + tc_name + " - PASS - " + append_to_tc_result
		print "======================================================="
		client2.send_simple("DISABLE_NETWORK " + str(int(tc_index)-1))
		client1.execute("ifconfig " + iface1 + " 0.0.0.0")
		client2.execute("ifconfig " + iface2 + " 0.0.0.0")
		client2.execute("killall wpa_supplicant")
		client1.execute("killall hostapd")
		os.remove(ap_config)
		client1.disconnect()
		client2.disconnect()
		sniffer.disconnect()
		return 0

	except:
		print "======================================================="
		print "TC RESULT - " + tc_name + " - FAIL"
		print "======================================================="
		sniffer.stop_sniffer()
		client1.local_execute("scp root@" + client1.ip + ":~/" + ap_log_file + " ./logs/")
		client2.local_execute("scp root@" + client2.ip + ":~/" + client_log_file + " ./logs/")
		client1.execute("ifconfig " + iface1 + " 0.0.0.0")
		client2.execute("ifconfig " + iface2 + " 0.0.0.0")
		client2.execute("killall wpa_supplicant")
		client1.execute("killall hostapd")
		os.remove(ap_config)
		traceback.print_exc()
		return -1

if len(argv) < 5:
	print __doc__ %argv[0]
	exit(-1)

tc_index = argv[5]

res = tc_wep(tc_name = "wep_tc%s" % tc_index, ap = argv[1], client = argv[2], ap_config_in = argv[3], client_config = argv[4], tc_index = tc_index)

print ""
print "TC result: ", res
print ""
exit(res)

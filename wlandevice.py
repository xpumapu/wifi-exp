#!/usr/bin/env python
import os
from subprocess import Popen, PIPE

nets_path = "/sys/class/net/"


class WlanDevice:
	""" Stores information about local wifi device (wifi card)"""
	phy = ""
	iface = ""
	mac_addr = ""
	pci_device = ""
	iface_type = ""

	def __init__(self, iface):	
		self.iface = iface

		phy_name_path = nets_path + iface + "/phy80211/name"
		phy_name = open(phy_name_path, "r").read()
		self.phy = phy_name.strip()

		addr_path = nets_path + self.iface + "/address"
		mac_addr = open(addr_path, "r").read()
		self.mac_addr = mac_addr.strip()

		pci_device_path = nets_path + iface + "/phy80211/device"
		pci_device = os.readlink(pci_device_path)
		self.pci_device = os.path.basename(pci_device)

		iw_cmd = ("iw", iface, "info")
		process = Popen(iw_cmd, stdout=PIPE, stderr=PIPE)
		(result, error_msg) = process.communicate()
		print result
		


	def print_info(self):
		print "=========="
		print "%s -> %s" % (self.iface, self.phy)
		print "MAC: %s" % self.mac_addr
		print "PCI dev: %s" % self.pci_device 
		print "=========="



def find_wlandevices():
	wifi_list = []
	nets = os.listdir(nets_path)

	for iface in nets:
		phy_path = nets_path + iface + "/phy80211/"
		if os.path.exists(phy_path):
			wifi_list.append(WlanDevice(iface))

	return wifi_list

   
  

def test_wlandevice():
	dev_list = find_wlandevices()
	print "Found %d wifi devices" % len(dev_list)
	for wifi in dev_list:
		wifi.print_info()


##################################
if __name__ == "__main__":
	test_wlandevice()


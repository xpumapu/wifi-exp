#!/usr/bin/env python
import os

nets_path = "/sys/class/net/"


class WlanDevice:
  """ Stores information about local wifi devicec (wifi cards)"""
  phy = []
  iface = []
  mac_addr = []
  pci_device = []

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


  def print_info(self):
    print "=========="
    print "%s -> %s" % (self.iface, self.phy)
    print "MAC: %s" % self.mac_addr
    print "PCI dev: %s" % self.pci_device 
    print "=========="



def main_func():
  nets = os.listdir(nets_path)

  wifi_list = []
  for iface in nets:
    phy_path = nets_path + iface + "/phy80211/"
    if os.path.exists(phy_path):
      wifi_list.append(WlanDevice(iface))
   
  print "Found %d wifi devices" % len(wifi_list)
  for wifi in wifi_list:
    wifi.print_info()


main_func()

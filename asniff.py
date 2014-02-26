#!/usr/bin/env python
from socket import *
from sys import *
import time
import commands
import threading
import subprocess
#from RemoteClient import RemoteClient
from sniffer import Sniffer
from subprocess import Popen






def test():
        ip = "127.0.0.1"
        iface = "moni0"
        log = "tc1.pcap"
	res = "tc1_res.pcap"
	text_res = "tc1_text_res.log"

        snif = Sniffer(ip = ip, iface = iface)
        snif.show_info()
        snif.set_log_file(log)

        #sniffer = RemoteClient(ip)

        #start snifer
        #delete old sniffer logs 

test()


#!/usr/bin/env python
from socket import *
import sys
import time
import signal
import commands
import threading
import subprocess, time
import os
import argparse
from parserfiles import ParserFiles
from subprocess import Popen, PIPE



class Sniffer(object):
	# machine IP addres
	ip = ""
	# machine monitor interface name
	iface = ""
	sniffer_file = "sniffer.pcap"
	sniffer_lock = threading.Lock()
	sniffing = False
	shell = None 
	tcpdump_pid = None
	tcpdump_cmd = None
	child = None
	
	def __init__(self, iface, ip = "127.0.0.1"):
		self.ip = ip
		self.iface = iface

	def show_info(self):
		print ""
		print "Sniffer IP: %s" % self.ip
		print "Sniffer interface: %s" % self.iface 
		print "Sniffer log file: %s" % self.sniffer_file
		print ""

	def sniff_bk(self,cmd1, cmd2, cmd3):
		args = (cmd1, cmd2, cmd3)
		tcpdump_proc = cmd3
		self.child = Popen(args, stdout=PIPE, stderr=PIPE)
		resu, erru = self.child.communicate()
		#print "resu " + resu
		#print "erru " + erru

		
	# execute command remotely
	def execrm(self, cmd):
		rm_machine = "root@" + self.ip
		rm_cmd = ("ssh", rm_machine, cmd)
		process = Popen(rm_cmd, stdout=PIPE, stderr=PIPE)
		(result, error_msg) = process.communicate()
		if error_msg:
			print "ERROR:"
			print error_msg

		return result

	# start sniffer and sniff in backgroung
	def start(self):
		if os.path.exists(self.sniffer_file) == True:
			rm_cmd = "rm -rfv %s" % self.sniffer_file
			res = self.execrm(rm_cmd)
			print res
		
	        self.tcpdump_cmd = "tcpdump -i %s -w %s" % (self.iface, self.sniffer_file)
		cmd = ('ssh', 'root@' + self.ip, self.tcpdump_cmd)
		self.thread = threading.Thread(target = self.sniff_bk, args=cmd)
		self.thread.start()
		print "Sniffer: start sniffing..."
		self.sniffing = True
		return self.thread

	# stop sniffer
	def stop(self):
		# sniffer was asked to stop
		ps_cmd = "ps -eo pid,args"

		result = self.execrm(ps_cmd)
		lines = result.splitlines()
		for line in lines:
			line = line.strip()
			(pid, cmdline) = line.split(' ', 1)
			if self.tcpdump_cmd in cmdline:
				self.tcpdump_pid = pid

		if self.tcpdump_pid != None:
			kill_cmd = "kill -SIGINT " +  self.tcpdump_pid
			result = self.execrm(kill_cmd)
			print "Sniffer: sniffing complete\n"

		if self.sniffing == True:
			self.sniffing = False

	def set_sniffer_files(self, pfiles):
		self.sniffer_file = pfiles.get_output_path()

def parse_input():
	inparser = argparse.ArgumentParser(description="capture air logs to <outfile>")
	inparser.add_argument("outfile", help="file name to store captured logs")
	args = inparser.parse_args()
	print "outfile ARG:" + args.outfile
	ip = "127.0.0.1"
	iface = "moni0"

	pfiles = ParserFiles()
	pfiles.set_output_file(args.outfile)

	return (pfiles, ip, iface)

def test_sniffer(pfiles, ip, iface):
	snif = Sniffer(ip = ip, iface = iface)
	snif.set_sniffer_files(pfiles)
	snif.show_info()

	#start snifer
	t = snif.start()
	time.sleep(5)
	snif.stop()


if __name__ == "__main__":
	(pfiles, ip, iface) = parse_input()
	test_sniffer(pfiles, ip, iface)


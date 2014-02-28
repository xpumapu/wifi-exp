#!/usr/bin/env python
from socket import *
from sys import *
import time
import signal
import commands
import threading
import subprocess, time
import os
from subprocess import Popen, PIPE



class Sniffer(object):
	ip = ""
	iface = ""
	log_file = "sniffer.pcap"
	sniffer_lock = threading.Lock()
	sniffing = False
	shell = None 
	
	def __init__(self, iface, ip = "127.0.0.1"):
		self.ip = ip
		self.iface = iface
		

	def show_info(self):
		print ""
		print "Sniffer IP: %s" % self.ip
		print "Sniffer interface: %s" % self.iface 
		print "Sniffer log file: %s" % self.log_file
		print ""

	def execute(self,cmd1, cmd2, cmd3):
		args = (cmd1, cmd2, cmd3)
		self.child = Popen(args)

		process = Popen(['ps', '-eo' ,'pid,args'], stdout=PIPE, stderr=PIPE)
		(result, notused) = process.communicate()
		lines = result.splitlines()
		for line in lines:
			line = line.strip()
			(pid, cmdline) = line.split(' ', 1)
			print "PID %s -> %s" % (pid, cmdline) 

		print "Sniffer: sniffing ...\n"
		self.sniffer_lock.acquire()
		print "Sniffer: sniffing complete\n"
		self.child.terminate() 
		self.child.wait()
		#print "sniffer return code:%d\n" % self.child.returncode
		self.sniffer_lock.release()

	# execute command remotely
	def execu(self, cmd):
		print "exec"	

	# start sniffer
	def start(self):
		if os.path.exists(self.log_file) == True:
			rm_cmd = "rm -rfv %s" % self.log_file
			subprocess.call(rm_cmd, shell = True)
		
	        sniffer_cmd = "tcpdump -i %s -w %s" % (self.iface, self.log_file)
		cmd = ('ssh', 'root@' + self.ip, sniffer_cmd)
		print "execute_sniffer: "
		print  cmd
		self.sniffer_lock.acquire()
		self.thread = threading.Thread(target = self.execute, args=cmd)
		self.thread.start()
		self.sniffing = True
		return self.thread

	# stop sniffer
	def stop(self):
		if self.sniffing == True:
			self.sniffer_lock.release()
			self.sniffing = False
			

	def set_log_file(self, log_file):
		self.log_file = os.path.join(os.getcwd(), log_file)


def test():
	ip = "127.0.0.1"
	iface = "eth0"
	log = "eth0.pcap"

	snif = Sniffer(ip = ip, iface = iface)
	snif.show_info()
	snif.set_log_file(log)
	snif.show_info()


	#start snifer
	t = snif.start()
	time.sleep(2)
	snif.stop()

        #delete old sniffer logs 
        

test()


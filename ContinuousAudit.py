#!/usr/bin/python3
import datetime
import argparse
import ipaddress
import os
import socket
import subprocess
import sys
import threading
import glob
from queue import Queue

#############################################################################
# Configurations
#############################################################################
MAX_THREADS = 256
TCP_TIMEOUT = 5
ICMP_COUNT = 1
ICMP_WAIT = 4

#############################################################################
# ICMP Checks
#############################################################################
def icmp_check(ip):
	if os.name =='nt':
		p = subprocess.Popen('ping ' + str(ip),stdout=subprocess.PIPE)
	else:
		p = subprocess.Popen(['ping',str(ip),'-c',str(ICMP_COUNT),'-w',str(ICMP_WAIT)],stdout=subprocess.PIPE)
	p.wait()
	if p.poll():
		results.append("  [+] ICMP Test: " + str(ip) + " is down")
	else:
		results.append("  [-] ICMP Test: " + str(ip) + " is up")
	return

#############################################################################
# TCP Connection Methods
#############################################################################
def tcp_check(ip, low, high):
	for port in range(low,high):
		print(port)
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(TCP_TIMEOUT)
			s.connect((str(ip), port))
			s.shutdown(socket.SHUT_RDWR)
			results.append("  [-] Port " + str(port) + " Test: " + str(ip) + " is open.")
		except Exception as e:
			results.append("  [+] Port " + str(port) + " Test: " + str(ip) + " is unreachable:" + " " + str(e))
		finally:
			s.close()
	return

#############################################################################
# HEALTHCHECK:
# Includes tests for Ping Sweeping, TCP Connect Tests, and UDP Traffic
# analysis. TCP and UDP ports can be configured in the file.
#
# ICMP: Done
# TCP:  Done
#############################################################################
results = []
queue = Queue()

def audit(args):
	subnet = ipaddress.ip_network(args.target)
	ports = str(args.ports)

	# Creates worker threads for quicker execution
	for _ in range(MAX_THREADS):
		try:
			t = threading.Thread(target=_worker)
			t.daemon = True;
			t.start()
		except (KeyboardInterrupt, SystemExit):
			cleanup_stop_thread()
			sys.exit()

	# Queues up all IPs in the given subnet
	for ip in subnet:
		queue.put([ip,ports])

	# Waits for all IPs to finish processing
	queue.join()

	# Prints results
	results.sort()

	# Get log file names
	time = datetime.datetime.now().strftime('audit_%H%M%s%d%m%Y.log')
	latest = max(glob.glob('logs/*.*'), key=os.path.getmtime)
	current = datetime.datetime.now().strftime('audit_%H%M%s%d%m%Y.log')

	open('logs/'+current,'w').close()
	with open('logs/'+current,'a') as f:
		for line in results:
			f.write(line+'\n')

	compare(latest,current,time)

def _hostworker():
	while True:
		arg = queue.get()
		icmp_check(arg[0])
		ports = arg[1].split("-")
		tcp_check(arg[0],int(ports[0]),int(ports[1]))		
		queue.task_done()

def compare(latest,current,time):
	with open(latest,'r') as f:
		d=set(f.readlines())

	with open('logs/'+current,'r') as f:
		e=set(f.readlines())

	open('audit/difference' + time + '.txt','w').close()

	with open('audit/difference' + time + '.txt','a') as f:
		for line in list(d-e):
			f.write(line)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', action="store", dest="target", type=str,
						help='target subnet in CIDR notation', required=True)
	parser.add_argument('-p', '--ports', action="store", dest="ports", type=str,
						help='ports to scan (format should be xx-xxx)', required=True)
	args = parser.parse_args()
	audit(args)

if __name__ == '__main__':
	main()

#!/usr/bin/env python
# encoding: utf-8

import locale
import os
import pcap
import sys
import time

from device_types import *

locale.setlocale(locale.LC_ALL, 'en_US')
devices = {}
time_format = "%Y-%m-%d %H:%M:%S"
table_format = "{:20} {:13} {:10} {:13} {:22} {:20}"

# a list of addresses (or prefixes) which we do not count
filtered_addresses = [

	# broadcast
	"ff:ff:ff:ff:ff:ff",

	# spanning tree
	"01:80:c2",

	# ipv4
	"01:00:5e",
	
	# ipv6
	"33:33:00",
	"33:33:ff",
]

def device_type(addr):
	""" Gets the name of the manufacturer of the device. """
	for t in device_types:
		for pfx in device_types[t]:
			if addr.startswith(pfx):
				return t
	return "Unknown"

def human_addr(addr):
	""" Turns a MAC address into human readable form. """
	return ":".join(map(lambda a: "%02x" % ord(a), addr))

def is_request_to_send(data):
	""" Check if a packet is a request-to-send packet. """
	return len(data) == 45 and ord(data[25]) == 0xb4 and ord(data[26]) == 0x00

def sp(number, singular, plural):
	""" Return either a singular or plural form of a noun based on a number. """
	return singular if number == 1 else plural

def now():
	""" Gets the current date and time. """
	return time.strftime(time_format)

def seconds_between(start, end):
	""" Gets the number of seconds between two times. """
	t_start = time.strptime(start, time_format)
	t_end = time.strptime(end, time_format)
	return time.mktime(t_end) - time.mktime(t_start)

def human_duration(timespan):
	""" Turns a number of seconds into a human readable string. """
	
	# seconds
	_s = timespan % 60
	timespan = (timespan - _s) / 60
	
	# minutes
	_m = timespan % 60
	timespan = (timespan - _m) / 60
	
	# hours
	_h = timespan % 24
	timespan = (timespan - _h) / 24
	
	# days
	_d = timespan

	# turn it into a string
	dur = []
	if _d > 0:
		dur.append("{:.0f} {}".format(_d, sp(_d, "day", "days")))
	if _h > 0:
		dur.append("{:.0f} {}".format(_h, sp(_h, "hour", "hours")))
	if _m > 0:
		dur.append("{:.0f} {}".format(_m, sp(_m, "minute", "minutes")))
	if _s > 0:
		dur.append("{:.0f} {}".format(_s, sp(_s, "second", "seconds")))
	
	if len(dur) == 0:
		return "a single moment"
	if len(dur) > 2:
		return ", ".join(dur[:-1]) + " and " + dur[-1]
	return " and ".join(dur)

def get_mac_address(interface):
	""" get the mac address (human readable form) from a given interface. """
	try:
		line = os.popen("ifconfig {} | grep ether".format(interface)).read()
		return line.split()[1]
	except:
		print "error: could not get mac address from device " + interface
		exit(0)

def ignore(addr):
	""" Returns whether or not the address should be ignored. """
	for a in filtered_addresses:
		if addr.startswith(a):
			return True
	return False

def saw_addr(addr, direction):
	""" Tells the database that a MAC address was just seen.
		
		direction: out/in """
	
	# skip this device's own address, broadcast, etc.
	if ignore(addr):
		return
	
	# create initial structure
	if not addr in devices:
		devices[addr] = {'addr':addr, 'packets_out':0, 'packets_in':0, 'first_seen': now(), 'last_seen':now()}

	# update data
	devices[addr]['packets_' + direction] += 1
	devices[addr]['last_seen'] = now()

def catch_packet(pktlen, data, timestamp):
	""" Callback when a single packet is captured. """
	
	# skip bad packets
	if not data:
		return
		
	# we only look for request-to-send packets
	if not is_request_to_send(data):
		return

	# update database
	saw_addr(human_addr(data[29:35]), 'in')
	saw_addr(human_addr(data[35:41]), 'out')

	#print "got package of %d bytes" % pktlen

	# update output line
	sys.stdout.write("\rhave seen {} devices so far \033[K".format(len(devices)))
	sys.stdout.flush()

def print_device(device):
	""" Prints a row with information about a device. """
	
	addr = device['addr']
	pkt_out = locale.format("%d", device['packets_out'], grouping=True)
	pkt_in = locale.format("%d", device['packets_in'], grouping=True)
	seen_fst = device['first_seen']
	seen_lst = device['last_seen']
	t = device_type(addr)
	
	print(table_format.format(addr, t, pkt_out, pkt_in, seen_fst, seen_lst))

def print_results():
	""" Prints a table with all seen devices. """
	
	hdr = table_format.format("address", "type", "sent", "received", "first seen", "last seen")
	
	
	if len(devices) > 0:
		print "these devices were seen:"
		print ""
		print hdr
		print len(hdr) * "-"
		for d in devices:
			print_device(devices[d])
		print ""

	duration = human_duration(seconds_between(time_start, time_end))
	print "a total of {} devices were seen over a duration of {}".format(len(devices), duration)

time_start = now()
time_end = now()
if __name__ == '__main__':
	
	if len(sys.argv) > 1 and sys.argv[1] == "-h":
		print "usage: %s [interface]" % sys.argv[0]
		exit(0)
	
	print "device_sniffer\nv0.1 by ephracis\n"
	
	p = pcap.pcapObject()

	# get interface
	inf = pcap.lookupdev()
	if len(sys.argv) > 1:
		inf = sys.argv[1]
	print "sniffing on interface: %s" % inf

	# get properties of interface
	mac = get_mac_address(inf)
	filtered_addresses.append(mac)

	# set monitor mode
	#try:
	#p.set_rfmon()
	#except:
	#	print "warning: could not enter monitor mode"

	# start capture session in promiscious mode
	p.open_live(inf, 1600, 1, 100)
	sys.stdout.write("have seen 0 devices so far ")
	sys.stdout.flush()
	try:
		while 1:
			p.dispatch(1, catch_packet)

	except KeyboardInterrupt:
		time_end = now()
		print ""
		print "shutting down"
		print_results()
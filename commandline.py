# this file contains code for parsing command line arguments.

import argparse

def parseArgs():
	""" Parse command line arguments and return a command line argument object. """
	
	parser = argparse.ArgumentParser(
		prog='device_sniffer',
		description='spot nearby devices using a wireless sniffer.',
		usage='%(prog)s <mode> [options]')
	
	parser.add_argument('--interface','-i', help="interface to scan on.", dest="inf", type=str)
	parser.add_argument('--verbse','-v', help="show extra output.", dest="verbosity", action="count")
	parser.add_argument('types', help="type of devices to scan for.", choices=['connected', 'scanning','both'], default='both', nargs='?')
	args = parser.parse_args()
	return args
#!/usr/bin/env python2
import re
import sys
import argparse
from urlparse import urlparse
DEBUG = False

# Result classes

class NmapResult:

	def __init__(self, ip, domain, port, status, protocol, line):
		self.ip       = ip
		self.domain   = domain or ""
		self.port     = port
		self.status   = status
		self.protocol = protocol
		self.line     = line

	def __format__(self, spec):
		host = self.ip
		if "d" in spec:
			host = self.domain if self.domain != "" else self.ip 
		return "{}:{}".format(host, self.port)


class URLResult(NmapResult):

	SSL_REGEX = re.compile("/ssl\|http")

	def __init__(self, ip, domain, port, status, protocol, line):
		NmapResult.__init__(self, ip, domain, port, status, protocol, line)
		self.is_ssl = (URLResult.SSL_REGEX.search(self.line) is not None)
		self.schema = "https" if self.is_ssl else "http"
		

	def __format__(self, spec):
		host = self.ip
		if "d" in spec:
			host = self.domain if self.domain != "" else self.ip 

		url = urlparse("{}://{}:{}/".format(self.schema, host, self.port))
		return url.geturl()

def debug(extra):
	if DEBUG:
		print("DEBUG: "+extra)


def usage():
	whoami = sys.argv[0]
	print("{} PATH.gnmap NEEDLE".format(whoami))
	print("find open ports in nmap gnmap that match NEEDLE and outout as IP:PORT, one per line")

def parse_gnmap(file, needle, status="open", protocol="tcp", factory=NmapResult):
	CASE_SENSITIVE = 0 if args.case_sensitive else re.IGNORECASE
	IP_AND_PORTS_REGEX = re.compile('^Host: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) \((.*?)\)\\tPorts: (.*?)[\\t\z]')
	NEEDLE_REGEX_STR   = ("([0-9]+)/({})/({})/[^,\\t\z]*?".format(status, protocol))+needle+'[^,\\t\z]*?/[,\\t\z]'
	NEEDLE_REGEX = re.compile(NEEDLE_REGEX_STR, re.MULTILINE | CASE_SENSITIVE)
	debug("needle regex = {}".format(NEEDLE_REGEX_STR))
	line = file.readline()
	while line:
		line_match = IP_AND_PORTS_REGEX.match(line)
		if line_match:
			ip       = line_match.group(1)
			hostname = line_match.group(2)
			ports    = line_match.group(3)
			debug(ports)
			find_needle = NEEDLE_REGEX.finditer(ports)
			if find_needle:
				for found in find_needle:
					port     = found.group(1)
					status   = found.group(2)
					protocol = found.group(3)
					nline    = found.group(0)
					result   = factory(ip, hostname, port, status, protocol, nline)
					yield result
		line = file.readline()



def parse_args():
	FACTORIES = ['plain', 'url']

	PROTOCOLS = ['tcp', 'udp', 'any']

	DEFAULTS  = {'mode':'simple', 
				 'secondary_search':None,
				 'status':'open',
				 'PATH':None,
				 'grep':None,
				 'domain':'never',
				 'case_sensitive':False,
				 'protocol':'any',
				 'factory':None}

	FACTORY_MAP = {'plain':NmapResult,
				   'url':URLResult}

	secondary_search = None
	factory = None
	parser = argparse.ArgumentParser(description='Transmorgify nmap greppable results')
	parser.set_defaults(**DEFAULTS)
	parser.add_argument("-g", "--grep", type=str, help="search nmap results for term", default=None)
	parser.add_argument("PATH", type=argparse.FileType(), help="path for .gnmap file to transmorgify")
	parser.add_argument("-K", "--case-sensitive", action="store_true", help="turn on case sensitivity", default=False, dest="case_sensitive")
	parser.add_argument("-s", "--status", type=str, help="show ports that have status STATUS i.e. open, closed etc", default="open")
	parser.add_argument("-p", "--protocol", choices=PROTOCOLS, help="show ports with protocol", default="any")
	parser.add_argument("-d", "--domain", choices=["must", "try", "never"], help="when to use domain names over IPs", default="never")
	parser.add_argument("-u", "--urls", dest="mode", action="store_const", const="url", help="extract urls")
	parser.add_argument("-f", "--factory", choices=FACTORIES, help="force object factory")
	args = parser.parse_args()

	if args.PATH is None:
		print("PATH must be specified!")
		parser.print_help()
		exit(1)

	if args.mode == "url":
		args.factory = args.factory or 'url'
		args.secondary_search = args.grep
		args.grep = "http"
		args.protocol = "tcp"

	args.factory = args.factory or "plain"
	args.factory = FACTORY_MAP[args.factory]

	if args.protocol == "any":
		args.protocol = ".*?"

	if args.grep is None:
		args.grep = ""

	return args

def process_args(args):
	CASE_SENSITIVE = 0 if args.case_sensitive else re.IGNORECASE
	needle = args.secondary_search or ""

	for result in parse_gnmap(file=args.PATH, needle=args.grep, status=args.status, factory=args.factory):
		
		if args.domain == "must" and result.domain == "":
			continue

		if args.secondary_search is not None:
			NEEDLE_REGEX_STR   = ("([0-9]+)/({})/({})/.*?".format(result.status, result.protocol))+needle+'.*?/[,\\t\z]'
			NEEDLE_REGEX = re.compile(NEEDLE_REGEX_STR, re.MULTILINE | CASE_SENSITIVE)
			if not NEEDLE_REGEX.search(result.line):
				continue

		domain_format = ""
		if args.domain in ["must", "try"]:
			domain_format="d"
		format_spec = "{}".format(domain_format)
		result_format = "{:"+format_spec+"}"
		print(result_format.format(result))

args = parse_args()
process_args(args)



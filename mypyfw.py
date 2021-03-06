#!/usr/bin/python
# 
# V1-0 by Joerg Stephan <joerg DOT stephan AT ymail DOT com>
# https://github.com/johestephan/mypyapachefw.git
# Copyright (c) 2014,2015 Joerg Stephan under BSD licence
#

import sys
import re
import datetime
from optparse import OptionParser
from geoip import geolite2






def iptablesDrop(IP):
    import iptc
    try:
		rule = iptc.Rule()
		rule.in_interface = options.interface
		rule.src = IP
		rule.create_target("DROP")
		chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
		chain.insert_rule(rule)
    except:
		print "Unexpected error (iptables):", sys.exc_info()[0]
		return
        

def pfDrop(IP):
    import pf
    import socket
    filter = pf.PacketFilter()
    blockip = pf.PFAddr(IP)
    try:
		filter.enable()
		ext_if = pf.PFAddr(type=pf.PF_ADDR_DYNIFTL, ifname=options.interface)
		ruling = pf.PFRule(action=pf.PF_DROP,
               		direction=pf.PF_IN,
		 	af=socket.AF_INET, 
               		quick=True,
               		src=pf.PFRuleAddr(blockip))
		#rs = pf.PFRuleset()
		rs = filter.get_ruleset()
		rs.append(ruling)

		# Load rules
		#filter = pf.PacketFilter()
		filter.load_ruleset(rs)
    except:
		print "Unexpected error (pf):", sys.exc_info()[0]
		return


def Getrcursivecheck(request, IP):
    try:
	weightcounter = request.count("/")
	if weightcounter > 15:
		print str(datetime.datetime.now()) + " " + request + " RecursiveCounter: " + str(weightcounter) + " Blocked: " + IP
		return True
	else:
		return False
    except:
	print "Unexpected error (GET_recursive):", sys.exc_info()[0]
        return False


def GETanalyzer(request, IP):
    try:
	weightcounter = 0
	infectionlist = ["select","union","from","where","join"]
	for rule in infectionlist:
	    imatch = re.search(rule,request)
	    if imatch is not None:
	        weightcounter +=1
	if weightcounter > 1:
	    if re.match(r"select (?:[^;]|(?:'.*?'))* from", request) is not None:
	        print str(datetime.datetime.now()) + " " + request + " InjectCounter: " + str(weightcounter) + " Blocked: " + IP
                return True
	else:
            return False
    except:
        print "Unexpected error (GET):", sys.exc_info()[0]
        return False


def HEADERanalyzer(line):
    try:
	xcounter = 0
	IP = line.split()[options.IPpos] # May need to be adjust, default 0 should work, combined is 1
	Request = line.split('"')[1].lower()
	Client = line.split('"')[-2]
	logstring = str(datetime.datetime.now()) + " " + IP + " Header: " + Client 
	m = re.search(blacklist,Client) # related services
	i = re.search(whitelist,IP) # Whitelabeld IP's
	if ( m is not None) or ( GETanalyzer(Request,IP) ) or ( Getrcursivecheck(Request,IP) ):
		if ( m is not None):
			logstring += " Matched Rule: " + str(m.group(0)) 
		if ( i is None ) :
			if not any(IP in s for s in recent):
				if options.geoip:
					match = geolite2.lookup(IP)
					if match is not None:
						logstring += " Country: " + match.country
			print logstring
			xcounter += 1
    			if  not options.tryrun:
				recent.append(IP)
			else:
				if options.enable_pf:
					pfDrop(IP)
				else:
					iptablesDrop(IP)
	return xcounter
    except:
        print "Unexpected error (Header):", sys.exc_info()
        return 0


parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="write report to FILE, default is /var/log/mypyfw.log", metavar="FILE")
parser.add_option("-i", "--ippos", dest="IPpos", type="int",
		  help="adjust IP position, default is 0", metavar="IPPOSITION")
parser.add_option("-b", "--blacklist", dest="blacklist", default="./conf.d/MatchList",
		  help="path to blacklist, default values are Hardcoded", metavar="FILE")
parser.add_option("-w", "--whitelist", dest="whitelist", default="./conf.d/IPWhiteList",
		  help="path to Whitelist, default values are Hardcoded", metavar="FILE")
parser.add_option("-t", "--try-run", action="store_false", dest="tryrun", default=True,
		  help=" you want a test run")
parser.add_option("-g", "--geoIP", action="store_true", dest="geoip", default=False,
		  help="add GeoIP data to output")
parser.add_option("-p", "--pf", action="store_true", dest="enable_pf", default=False,
		  help="use PF as firewall (ex. on openBSD)")
parser.add_option("-n", "--net", dest="interface", default="eth0",
		  help=" set iptables/pf network interface")
parser.add_option("-s", "--inputstream", dest="streamsource",
		  help="Apache Log file to follow stream", metavar="FILE")


(options, args) = parser.parse_args()

blacklist = "Wget|Python|sqlmap|curl|apach0day"
whitelist = "127.0.0.1|::1"

# Parsing Options
if (options.filename is None): 
    options.filename = "/var/log/mypyfw.log"

if (options.IPpos is None):
    options.IPpos = 1

if (options.blacklist is not None): 
    for line in open(options.blacklist, "r") :
        blacklist = blacklist +"|" + line.rstrip()
    print "extended Blacklist: " + blacklist
        
if (options.whitelist is not None): 
    for line in open(options.whitelist, "r") :
        whitelist = whitelist + "|" + line.rstrip()
    print "extended Whitelist: " + whitelist

logf = open(options.filename,'a')
sys.stdout = logf
recent = list()
counter = 0
        
if (options.streamsource is not None):
	source = open(options.streamsource,'r')
else:
	source = sys.stdin

for line in source:
    counter += HEADERanalyzer(line)
    
    
    
logf.close()
sys.stdout = sys.__stdout__

print "Blocked " + str(counter) + " IP Addresses in this run"
  

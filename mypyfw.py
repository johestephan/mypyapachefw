#!/usr/bin/python
# 
# V1-0 by Joerg Stephan <joerg DOT stephan AT owasp DOT org>
# https://github.com/johestephan/mypyapachefw.git
# Copyright (c) 2014 Joerg Stephan under BSD licence
#

import iptc
import sys
import re
import datetime
from optparse import OptionParser
from geoip import geolite2

def ipfwDrop(IP):
    try:
        rule = iptc.Rule()
        rule.in_interface = "eth0"
        rule.src = IP
        rule.create_target("DROP")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        return

    

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="write report to FILE, default is /var/log/mypyfw.log", metavar="FILE")
parser.add_option("-i", "--ippos", dest="IPpos", type="int",
		  help="adjust IP position, default is 0", metavar="IPPOSITION")
parser.add_option("-b", "--blacklist", dest="blacklist",
		  help="path to blacklist, default values are Hardcoded", metavar="FILE")
parser.add_option("-w", "--whitelist", dest="whitelist", type="int",
		  help="path to Whitelist, default values are Hardcoded", metavar="FILE")
parser.add_option("-t", "--try-run", action="store_false", dest="verbose", default=False,
		  help=" you want a test run")
parser.add_option("-g", "--geoIP", action="store_false", dest="geoip", default=False,
		  help="add GeoIP data to output")
(options, args) = parser.parse_args()

blacklist = "Wget|Python|sqlmap|curl|-"
whitelist = "127.0.0.1|::1"

# Parsing Options
if (options.filename is None): 
    options.filename = "/var/log/mypyfw.log"

if (options.IPpos is None):
    options.IPpos = 1
    
if (options.blacklist is not None): 
    for line in open(options.blacklist, "r") :
        blacklist = blacklist +"|" + line.rstrip()
    print blacklist
        
if (options.whitelist is not None): 
    for line in open(options.whitelist, "r") :
        whitelist = whitelist + "|" + line.rstrip()
        
logf = open(options.filename,'a')
sys.stdout = logf
recent = list()

for line in sys.stdin:
    IP = line.split()[options.IPpos] # May need to be adjust, default 0 should work, combined is 1
    Client = line.split('"')[-2]
    logstring = str(datetime.datetime.now()) + " " + IP + " Header: " + Client 
    m = re.search(blacklist,Client) # related services
    i = re.search(whitelist,IP) # Whitelabeld IP's
    if ( m is not None):
        logstring += "Matched Rule: " + str(m.group(0)) 
        if ( i is None ):
            if not any(IP in s for s in recent):
                if options.geoip is not none:
                    match = geolite2.lookup('17.0.0.1')
                    if match is not None:
                        logstring += " Country: " + match.country
                print logstring
              	if  not options.tryrun:
                    ipfwDROP(IP)
  
logf.close()
sys.stdout = sys.__stdout__


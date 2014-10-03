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
        raise

    

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="write report to FILE", metavar="FILE")
parser.add_option("-i", "--ippos", dest="IPpos", type="int",
		  help="adjust IP position, default is 0", metavar="IPPOSITION")
parser.add_option("-b", "--blacklist", dest="blacklist",
		  help="path to blacklist, default values are Hardcoded", metavar="FILE")
parser.add_option("-w", "--whitelist", dest="whitelist", type="int",
		  help="path to Whitelist, default values are Hardcoded", metavar="FILE")
(options, args) = parser.parse_args()

# Parsing Options
if (options.filename is None): 
    options.filename = "/var/log/mypyfw.log"

if (options.IPpos is None):
    options.IPpos = 1
    
if (options.blacklist is None): 
    blacklist = 'Wget|Python|sqlmap|curl|-'
else:
    for line in open(options.blacklist, "r") :
        blacklist = blacklist +"|" + line.rstrip()
        
if (options.whitelist is None): 
    options.whitelist = '127.0.0.1|::1'
else:
    for line in open(options.whitelist, "r") :
        whitelist = whitelist + "|" + line.rstrip()
        
logf = open(options.filename,'a')
sys.stdout = logf
recent = list()

for line in sys.stdin:
    IP = line.split()[options.IPpos] # May need to be adjust, default 0 should work, combined is 1
    Client = line.split('"')[-2]
    m = re.search(blacklist,Client) # related services
    i = re.search(whitelist,IP) # Whitelabeld IP's
    if ( m is not None):
        if ( i is None ):
            if not any(IP in s for s in recent):
                print str(datetime.datetime.now()) + " " +IP + " Header: " + Client + " Matched Rule: " + str(m.group(0))
              	ipfwDROP(IP)
  
logf.close()
sys.stdout = sys.__stdout__


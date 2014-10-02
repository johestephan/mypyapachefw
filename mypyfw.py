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


parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="write report to FILE", metavar="FILE")
parser.add_option("-i", "--ippos", dest="IPpos", type="int",
		  help="adjust IP position, default is 0", metavar="IPPOSITION")
(options, args) = parser.parse_args()

if (options.filename is None): 
    options.filename = "/var/log/mypyfw.log"
if (options.IPpos is None):
    options.IPpos = 1

logf = open(options.filename,'a')
sys.stdout = logf
recent = list()

for line in sys.stdin:
    IP = line.split()[options.IPpos] # May need to be adjust, default 0 should work, combined is 1
    Client = line.split('"')[-2]
    m = re.search('Wget|Python|sqlmap|curl|-',Client) # related services
    i = re.search('127.0.0.1|::1|87.179.164.194',IP) # Whitelabeld IP's
    if ( m is not None):
        if ( i is None ):
            if not any(IP in s for s in recent):
                print str(datetime.datetime.now()) + " " +IP + " Header: " + Client + " Matched Rule: " + str(m.group(0))
                recent.append(IP)
                rule = iptc.Rule()
                rule.in_interface = "eth0"
                rule.src = IP
                rule.create_target("DROP")
                chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                chain.insert_rule(rule)
logf.close()
sys.stdout = sys.__stdout__


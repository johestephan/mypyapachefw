#!/usr/bin/python
# 
# V1-0 by Joerg Stephan <joerg DOT stephan AT owasp DOT org>
# https://github.com/johestephan/mypyapachefw.git

import iptc
import sys
import re
import datetime

recent = list()
for line in sys.stdin:
    IP = line.split()[1] # May need to be adjust, default 0 should work, combined is 1
    Client = line.split('"')[-2]
    m = re.search('Wget|Python|sqlmap|curl',Client) # related services
    i = re.search('127.0.0.1|87.179.164.194',IP) # Whitelabeld IP's
    if ( m is not None):
        if ( i is None ):
            if not any(IP in s for s in recent):
                print str(datetime.datetime.now()) + " " +IP + " Header: " + Client + " Matched Rule: " + str(m.group(0))
                recent.insert(0, IP)
                rule = iptc.Rule()
                rule.in_interface = "eth0"
                rule.src = IP
                rule.create_target("DROP")
                chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                chain.insert_rule(rule)


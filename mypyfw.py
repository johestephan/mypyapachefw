#!/usr/bin/python
# 
# V1-0 by Joerg Stephan <joerg DOT stephan AT owasp DOT org>
# https://github.com/johestephan/mypyapachefw.git

import iptc
import sys
import re

recent = list()
for line in sys.stdin:
    IP = line.split()[0]
    Client = line.split('"')[-2]
    m = re.search('Wget|Python|sqlmap',Client) # related services
    i = re.search('127.0.0.1',IP) # Whitelabeld IP's
    if ( m is not None):
        if ( i is None ):
            if not any(IP in s for s in recent):
                print IP + " " + Client
                recent.insert(0, IP)
                rule = iptc.Rule()
                rule.in_interface = "eth0"
                rule.src = IP
                rule.create_target("DROP")
                chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                chain.insert_rule(rule)


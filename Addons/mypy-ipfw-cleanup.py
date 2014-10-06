#!usr/bin/python

import time, sys
import iptc

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, "INPUT")

try:
    table.autocommit = False
    for rule in chain.rules:
       (packets, bytes) = rule.get_counters()
       if int(packets) == 0:
          chain.delete_rule(rule)
    chain.zero_counters()
    table.commit()
    table.close()
except iptc.ip4tc.IPTCError: 
   print "Oops!" 
   

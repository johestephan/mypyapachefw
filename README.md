README - My Python Apache Firewall
=====
## Requires
* python iptables (pip install --upgrade python-iptables)

## Console run
* cat /var/log/apache2/access.log | python mypyfw.py

## Need to know
The IP split line may has an error.
By default the IP should be located at cell 0. If you use combined logging than it may is 1. 

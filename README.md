README - My Python Apache Firewall
=====
MyPyApache FW is a loganalyzer written in python.
The script will work on any access log you pipe in to it and will create iptables rules to block 
client ip addresses which may be malicious to the system.

Therefor it uses the Agent information from the Apache access log, and searches for "bad" agents, like curl, python, wget.

## Requires
* python iptables 
```
pip install --upgrade python-iptables
```
* python GeoIP
```
(fedora) yum install GeoIP GeoIP-dev
(ubuntu) apt-get install python-devel-all libgeoip-devel

pip install --upgrade GeoIP
pip install --upgrade python-geoip-geolite2
```
* python pf
```
pip install --upgrade py-pf
```
for use of pf (ex. openBSD, FreeBSD, NetBSD). 
 
## Usage
You need to run the script on console like
```
cat /var/log/apache2/access.log | python mypyfw.py
```
May you want to write a cronjob to do it every some minuits, and work with tail, like
```
*/30 * * * * tail -n 500 /var/log/apache2/other_vhosts_access.log | python /opt/mypyapachefw/mypyfw.py


```

## Help
```
Usage: mypyfw.py [options]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file=FILE  write report to FILE, default is /var/log/mypyfw.log
  -i IPPOSITION, --ippos=IPPOSITION
                        adjust IP position, default is 0
  -b FILE, --blacklist=FILE
                        path to blacklist, default values are Hardcoded
  -w FILE, --whitelist=FILE
                        path to Whitelist, default values are Hardcoded
  -t, --try-run          you want a test run
  -g, --geoIP           add GeoIP data to output
  -p, --pf              use PF as firewall (ex. on openBSD)
  -n INTERFACE, --net=INTERFACE
                         set iptables/pf network interface
```

## Addons
* I just added a iptables cleanup script. You can find it in Addons folder. The script will remove all rules which received 0 (zero) packages and will reset the package counter. So if you let it run once a day, it will always delete unused rules.

## Need to know
The IP split line may has an error.
By default the IP should be located at cell 1 (for combined logging). If you use the standard apache logging than it may is 0. 
```
cat /var/log/apache2/access.log | python mypyfw.py -i 0
```

## Current Rules
* Header: curl
* Header: python
* Header: sqlmap
* Header: - 
* Header: Wget

## Waranty
There is none! Use at own risk. Ping me for improvements.

## More Information
For more information please follow:
* [https://jsonsecurity.blogspot.de/] My Blog
* [http://jsonsecurity.blogspot.de/feeds/posts/mypyfw] RSS Feed

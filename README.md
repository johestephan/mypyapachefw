README - My Python Apache Firewall
=====
## Requires
* python iptables 
```
pip install --upgrade python-iptables
```
## Console run
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
  -f FILE, --file=FILE  write report to FILE
  -i IPPOSITION, --ippos=IPPOSITION
                        adjust IP position, default is 0
```

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

## More Information
For more information please follow:
* [https://jsonsecurity.blogger.com] My Blog
* [http://jsonsecurity.blogspot.de/feeds/posts/mypyfw] RSS Feed

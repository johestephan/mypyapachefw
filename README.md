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
May you want to write a cronjob to do it every some minuits, and work with tail
```
tail -n 1000 /var/log/apache2/access.log | python mypyfw.py

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


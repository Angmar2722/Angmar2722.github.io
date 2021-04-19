---
layout: page
title: Introduction
---
<hr/>

The introduction consists of 3 challenges. 

<br/>

# Finding Flags 

As shown in the image below, all you had to do was input the flag `crypto{y0ur_f1rst_fl4g}` into the submit box. So it seems that the flag format for all the cryptoHack challenges is `crypto{flag}`.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img4.png)

**Flag :** crypto{y0ur_f1rst_fl4g}

<br/>

# Great Snakes 

As shown in the image below, all you had to do was run the Great Snakes python program and then you would obtain the flag.

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img5.png)

The source code of the program : 

```python

#!/usr/bin/env python3

import sys
# import this

if sys.version_info.major == 2:
    print("You are running Python 2, which is no longer supported. Please update to Python 3.")

ords = [81, 64, 75, 66, 70, 93, 73, 72, 1, 92, 109, 2, 84, 109, 66, 75, 70, 90, 2, 92, 79]

print("Here is your flag:")
print("".join(chr(o ^ 0x32) for o in ords))

```

The flag is obtained after running the program :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img6.png)

**Flag :** crypto{z3n_0f_pyth0n}

<br/>

# Network Attacks 

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img15.png)

All I had to do was connect to the server and send a JSON object with the key `buy` and value `flag` in order to obtain the flag. To do that, I just slightly modified the `telnetlib_example.py` python script that they provided by changing the `request` JSON object to have a key of `buy` and value of `flag`. The modified code :

```python
#!/usr/bin/env python3

import telnetlib
import json

HOST = "socket.cryptohack.org"
PORT = 11112

tn = telnetlib.Telnet(HOST, PORT)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)


print(readline())
print(readline())
print(readline())
print(readline())


request = {
    "buy": "flag"
}
json_send(request)

response = json_recv()

print(response)
```
And as shown below after running the script, the flag is outputted :

![CryptoHack Image](/assets/img/exploitImages/cryptoHack/img14.png)

**Flag :** crypto{sh0pp1ng_f0r_fl4g5}



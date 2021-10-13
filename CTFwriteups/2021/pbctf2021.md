---
layout: page
title: Perfect Blue 2021 CTF Writeup
---
<hr/>

![Perfect Blue 2021 Writeup](/assets/img/ctfImages/2021/pbctf2021/logo.png)

I participated in <a href="https://ctftime.org/event/1371" target="_blank">Perfect Blue's 2021 CTF</a> over the weekend (Sat, 09 Oct. 2021, 08:00 SGT — Mon, 11 Oct. 2021, 08:00 SGT) playing as part of Social Engineering Experts. Me and Diamondroxxx managed to solve half of the crypto challs, the challenges were hard to say the least. 

The level of difficulty was on par with Google CTF 2021, there were no sanity checks or survey challenges hence the number of scoring teams was greatly reduced. In the end, we ranked 32<sup>nd</sup> out of 210 scoring teams (there were 1535 registered teams).

Crypto was hard :(

![Perfect Blue 2021 Writeup](/assets/img/ctfImages/2021/pbctf2021/img7.png)

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[GoodHash](#goodhash) | Crypto | 218 | 30 | 
|[Steroid Stream](#steroid-stream) | Crypto | 198 | 38 |
|[Ghost Writer](#ghost-writer) | Misc | 170 | 58 |
|[Alkaloid Stream](#alkaloid-stream) | Crypto | 134 | 132 |

<br/>

<br/>

## GoodHash

![Perfect Blue 2021 Writeup](/assets/img/ctfImages/2021/pbctf2021/img1.png)

The server source code provided :

```python

#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.number import *
from flag import flag
import json
import os
import string

ACCEPTABLE = string.ascii_letters + string.digits + string.punctuation + " "


class GoodHash:
    def __init__(self, v=b""):
        self.key = b"goodhashGOODHASH"
        self.buf = v

    def update(self, v):
        self.buf += v

    def digest(self):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.buf)
        enc, tag = cipher.encrypt_and_digest(b"\0" * 32)
        return enc + tag

    def hexdigest(self):
        return self.digest().hex()


if __name__ == "__main__":
    token = json.dumps({"token": os.urandom(16).hex(), "admin": False})
    token_hash = GoodHash(token.encode()).hexdigest()
    print(f"Body: {token}")
    print(f"Hash: {token_hash}")

    inp = input("> ")
    if len(inp) > 64 or any(v not in ACCEPTABLE for v in inp):
        print("Invalid input :(")
        exit(0)

    inp_hash = GoodHash(inp.encode()).hexdigest()

    if token_hash == inp_hash:
        try:
            token = json.loads(inp)
            if token["admin"] == True:
                print("Wow, how did you find a collision?")
                print(f"Here's the flag: {flag}")
            else:
                print("Nice try.")
                print("Now you need to set the admin value to True")
        except:
            print("Invalid input :(")
    else:
        print("Invalid input :(")
        
```

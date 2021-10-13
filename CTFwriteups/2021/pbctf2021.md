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

The objective of this challenge is pretty straightforward. A known 61 byte IV (the random 16 bytes plus other formatting) is generated and used for encrypting 32 bytes of zeroes using AES-GCM with a known constant key. Our objective is to provide another IV which consists of only printable ASCII characters (from 32 to 126) such that when encrypting the 32 bytes of zeroes with the same key, the same ciphertext is generated.

Hence we have to find a collision between the two IVs. The ciphertext generated is referred to as a hash in this challenge. This <a href="https://www.youtube.com/watch?v=g_eY7JXOc8U&t=2s" target="_blank">video</a> by David Wong provides a very good introduction to how the GCM mode of operation works. More importantly, the document <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf" target="_blank">NIST SP 800-38D</a> is especially useful because it fully explains all mechanisms underlying the GCM standard.

Reading the GCM specifications of the document (page 15), we can clearly see that if the length of the IV is not equal to 96 bytes as it is in our case (it is most commonly 96 bytes), a different mechanism for creating the IV is used. In that case:

$$ \text{Let} \quad  H \ = \ E_k(\text{16 bytes of zeroes})$$

$$ \text{Let} \quad s \ = \ (len(IV) \ mod \ 128)) \ mod \ 128 $$

$$ J_0 \ = \ GHASH_H(IV \ \Vert \ 0^{s \ + \ 64} \ \Vert \ len(IV)_{64} \ ) $$

Here \\( H \\) is known as the hash subkey and it will always be constant as it is simply the block cipher encryption (in our case AES) of 16 bytes or 128 bits of zeroes. The block \\( J_0 \\) is the pre-counter block and is constructed such that the IV is padded with the minimum number of 0 bits until the result is a multiple of 16 bytes (the block size). 

Obviously we are most interested in how the \\(GHASH_H \\) function works (hence the challenge name 'GoodHash') as if we can feed in two different IVs which can produce the same \\( GHASH_H \\), we would have produced two same ciphertexts and hence a collision (assuming the encryption key is constant as it is in our case) as long as the length of our different IV is the same as the original. This is due to the fact that the rest of the algorithm for GCM is the same for the two different IVs (as key, \\( GHASH_H \\), plaintext is constant).

Reading page 12 of the NIST documentation, the algorithm which defines \\(GHASH_H \\) is clearly outlined. Given the hash subkey \\( H \\), it is defined as follows:

$$ Let \quad \ X \ = \ X_1 \ \Vert X_2 \ \Vert X_3 \ \Vert \ ... \ \Vert X_{i - 1} \ \Vert X_i \quad \text{where} \  X_i \ \text{corresponds to some block in a sequence} $$

$$ \therefore \ GHASH_H \quad = \quad X_1 \cdot H^i \ \oplus \ X_2 \cdot H^{i - 1} \ \oplus \ ... \ \oplus \ X_{i - 1} \cdot H^2 \ \oplus \ X_i \cdot H $$



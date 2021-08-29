---
layout: page
title: Yauza 2021 CTF Writeup
---
<hr/>

![Yauza CTF 2021 Writeup](/assets/img/ctfImages/2021/yauza2021/logo.png)

Originally I wasn't planning to play any CTF during this weekend but Diamondroxxx asked me if I could as he and the other members of Social Engineering Experts were participating in <a href="https://ctftime.org/event/1417" target="_blank">Yauza CTF 2021</a>, a Soviet themed CTF. Me and Diamondroxxx solved all the crypto challenges in Yauza in a few hours so we decided to check out Fword CTF after that (writeups for that can be found <a href="https://angmar2722.github.io/CTFwriteups/2021/fword2021/" target="_blank">here</a>. 

We joined late for Yauza as it was Fri, 27 Aug. 2021, 20:00 SGT — Sun, 29 Aug. 2021, 20:00 SGT while we started playing at 9 am Saturday. In the end, we ranked 10<sup>th</sup> out of 226 scoring teams, focusing only on the crypto challenges :

![Yauza CTF 2021 Writeup](/assets/img/ctfImages/2021/yauza2021/img1.png)

We managed to solve all 3 crypto challenges (the scoring system was generous to say the least) :

![Yauza CTF 2021 Writeup](/assets/img/ctfImages/2021/yauza2021/img2.png)

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Signature](#signature) | Crypto | 9109 | 30 | 
|[Knapsack](#knapsack) | Crypto | 8856 | 35 | 
|[Signature](#signature) | Crypto | 7720 | 49 | 

<br/>

<br/>

## Signature

![Yauza CTF 2021 Writeup](/assets/img/ctfImages/2021/yauza2021/img3.png)

The server source code provided :

```python

from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes, size, getRandomNBitInteger
from storage import flag

def byten(x, n):
    return (x >> (n * 8)) & 0xFF

def mask(n):
    return (1 << n) - 1

def rotate(x, n, s):
    return ((x >> (s - n)) | (x << n)) & mask(s)

def scramble(x):
    magic = 0xC3A569C3A569C3A569C3A569C3A569C33C965A3C965A3C965A3C965A3C965A3C
    for i in range(32):
        x = rotate(x, 27, 256) ^ rotate(magic, i, 256)
    return x

def sha2(x):
    hash = SHA256.new()
    hash.update(x)
    return hash.digest()

def gen_pair():
    private = [getRandomNBitInteger(256) for _ in range(16)]
    public = [long_to_bytes(y) for y in private]
    for i in range(16):
        for j in range(255):
            public[i] = sha2(public[i])
    return private, [bytes_to_long(y) for y in public]


def sign(x, key):
    parts = [byten(x, i) for i in range(16)]

    digest = [long_to_bytes(y) for y in key]
    for i in range(16):
        for j in range(parts[i]):
            digest[i] = sha2(digest[i])

    return digest

def verify(x, sign, public):
    parts = [255 - byten(x, i) for i in range(16)]

    digest = list(sign)
    for i in range(16):
        for j in range(parts[i]):
            digest[i] = sha2(digest[i])
        if digest[i] != long_to_bytes(public[i]):
            return False
    return True


def do_signature(x, private):
    signature = sign(scramble(x), private)
    return bytes_to_long(b''.join(signature))

def do_verify(x, signature, public):
    signature = long_to_bytes(signature, 256*16//8)
    signature = [signature[i*32:(i + 1)*32] for i in range(16)]
    return verify(scramble(x), signature, public)


menu = '''\
[1] Sign message
[2] Get flag
[3] Quit'''

if __name__ == '__main__':
    private, public = gen_pair()
    challenge = getRandomNBitInteger(256)
    while True:
        try:
            print(menu)
            opt = input('> ')
            if opt == '1':
                data = int(input('msg: '))
                if size(data) > 256:
                    raise Exception('Message is too long (256 bits max)')
                if data == challenge:
                    raise Exception('Nice try')

                print(do_signature(data, private))
            elif opt == '2':
                print('Enter signature for the message:')
                print(challenge)
                data = int(input('sign: '))
                if size(data) > 256*16:
                    raise Exception('Signature is too long (16 blocks, 256 bits each)')
                if not do_verify(challenge, data, public):
                    raise Exception('Wrong signature')
                print(flag)
            elif opt == '3':
                exit(0)
            else:
                raise Exception('Unknown option')
        except Exception as ex:
            print('Error:', ex)
            
```

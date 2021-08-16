---
layout: page
title: InCTF 2021 CTF Writeup
---
<hr/>

![InCTF 2021 Writeup](/assets/img/ctfImages/inctf2021/logo.png)

During the weekend, I participated in Amrita University's <a href="https://ctftime.org/event/1370" target="_blank">InCTF 2021</a> event (Fri, 13 Aug. 2021, 21:30 SGT — Sun, 15 Aug. 2021, 21:30 SGT). I was part of my new team Social Engineering Experts and we ranked 22nd out of 604 scoring teams. I managed to solve only 4 challenges :

![InCTF 2021 Writeup](/assets/img/ctfImages/inctf2021/img1.png)

Timestamps of the challenges that I solved :

![InCTF 2021 Writeup](/assets/img/ctfImages/inctf2021/img2.png)

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Eazy Xchange](#eazy-xchange) | Crypto | 179 | 44 |
|[Right Now Generator](#right-now-generator) | Crypto | 100 | 51 |
|[Lost Baggage](#lost-baggage) | Crypto | 100 | 52 |
|[Gold-Digger](#gold-digger) | Crypto | 100 | 76 |

<br/>

<br/>

## Eazy Xchange

![InCTF 2021 Writeup](/assets/img/ctfImages/inctf2021/img3.png)

The Sage source code provided :

```python

import os, hashlib, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = os.urandom(4)
FLAG = open('flag.txt', 'rb').read()
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

def gen_key(G, pvkey):
	G = sum([i*G for i in pvkey])
	return G

def encrypt(msg, key):
	key = hashlib.sha256(str(key).encode()).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
	return {'cip': cipher.encrypt(pad(msg, 16)).hex(), 'iv': cipher.IV.hex()}

def gen_bob_key(EC, G):
	bkey = os.urandom(4)
	B = gen_key(G, bkey)
	return B, bkey

def main():
	EC = EllipticCurve(GF(p), [a, b])
	G = EC.gens()[0]
	Bx = int(input("Enter Bob X value: "))
	By = int(input("Enter Bob Y value: "))
	B = EC(Bx, By)
	P = gen_key(G, key)
	SS = gen_key(B, key)
	cip = encrypt(FLAG, SS.xy()[0])
	cip['G'] = str(G)
	return cip

if __name__ == '__main__':
	cip = main()
	pickle.dump(cip, open('enc.pickle', 'wb'))

```

The file with the ciphertext and IV can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2021/inctf2021/eazyXchange/enc.pickle" target="_blank">here</a>.


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

The file with the ciphertext and IV can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2021/inctf2021/eazyXchange/enc.pickle" target="_blank">here</a>. The cryptosystem implemeted here is <a href="https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman" target="_blank">ECDH</a> (Elliptic Curve Diffie-Hellman) key exchange. The gist of it can be seen in the image below :

![InCTF 2021 Writeup](/assets/img/ctfImages/inctf2021/img5.png)

The function `gen_bob_key` generates Bob's private key d<sub>B</sub> but it has a serious vulnerability as it uses the function `gen_key` which returns the sum of 4 unknown bytes. Although there are 256<sup>4</sup> possibilities for the 4 bytes, since the sum is returned as the private key, there can only be a maximum value of 1020 (255 * 4) with in-between values being different combinations of 4 bytes. Alice's private key D<sub>a</sub> is also generated using `gen_key` hence it too will have only a maximum value of 1020. Alice's public key Q<sub>a</sub> is calculated by Q<sub>a</sub> = D<sub>a</sub> * G which is the result of adding G to itself d times as explained above. G or the generator point can be caluclated as curve parameters are given. By running two loops till 1020 in order to guess the correct private keys for both, the shared secret (SS) can be quickly calculated as SS = d<sub>B</sub> * Q<sub>a</sub>. Note that this is the x-coordinate of SS hence in the solve script, `SS = d<sub>B</sub> * Q<sub>a</sub>.xy()[0]` is used. From there, the shared secret can be used as the key to decrypt the AES-CBC ciphertext to get the flag.

The Sage solve script :

```python

import pickle
import os, hashlib, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

with open("enc.pickle", "rb") as f:
    given = pickle.load(f)

print(given)

ct = given["cip"]
givenIV = given["iv"]

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

EC = EllipticCurve(GF(p), [a, b])
G = EC.gens()[0]

def decrypt(key, msg):
	key = hashlib.sha256(str(key).encode()).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(givenIV))
	return cipher.decrypt(msg)

for i in range(1021):
    print(i)
    #bobPrvKeyGuess = i
    #i = 423 is answer
    for alicePubKeyGuess in range(1021):
        try:
            SS = (i * alicePubKeyGuess * G).xy()[0]
            flagGuess = decrypt(SS, bytes.fromhex(ct))
        except ZeroDivisionError:
            continue
        if(flagGuess[:6] == b"inctf{"):
            print("")
            print(flagGuess)
            exit(0)
	    
```

<p> <b>Flag :</b> inctf{w0w_DH_15_5o_c00l!_3c9cdad74c27d1fc} </p>

<br/>

## Right Now Generator

![InCTF 2021 Writeup](/assets/img/ctfImages/inctf2021/img4.png)

The source code provided :

```python

#!/usr/bin/env python3

import random, hashlib, os, gmpy2, pickle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = open('flag.txt', 'rb').read()

class RNG():
	pad = 0xDEADC0DE
	sze = 64
	mod = int(gmpy2.next_prime(2**sze))

	def __init__(self, seed_val, seed=None):
		if seed == None:
			assert seed_val.bit_length() == 64*2, "Seed is not 128 bits!"
			self.seed = self.gen_seed(seed_val)
			self.wrap()
		else:
			self.seed = seed
			self.ctr = 0

	def gen_seed(self, val):
		ret = [val % self.mod]
		val >>= self.sze
		for i in range(self.sze - 1):
			val = pow(i ^ ret[i] ^ self.pad, 3, self.mod)
			ret.append(val % self.mod)
			val >>= self.sze
		return ret

	def wrap(self, pr=True):
		hsze = self.sze//2
		for i in range(self.sze):
			r1 = self.seed[i]
			r2 = self.seed[(i+hsze)%self.sze]
			self.seed[i] = ((r1^self.pad)*r2)%self.mod
		self.ctr = 0

	def next(self):
		a, b, c, d = (self.seed[self.ctr^i] for i in range(4))
		mod = self.mod
		k = 1 if self.ctr%2 else 2
		a, b, c, d = (k*a-b)%mod, (b-c)%mod, (c-d)%mod, (d-a)%mod
		self.ctr += 1
		if self.ctr==64:
			self.wrap(pr=False)
		return a

def encrypt(key: bytes, pt: bytes) -> bytes:
	key = hashlib.sha256(key).digest()[:16]
	cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
	return {'cip': cipher.encrypt(pad(pt, 16)).hex(), 'iv': cipher.IV.hex()}

def main():
	obj = RNG(random.getrandbits(128))
	out1 = ''.join([format(obj.next(), '016x') for i in range(64)])
	out2 = ''.join([format(obj.next(), '016x') for i in range(64)])
	cip = encrypt(bytes.fromhex(out1), FLAG)
	cip['leak'] = out2
	return cip

if __name__ == '__main__':
	cip = main()
	pickle.dump(cip, open('enc.pickle', 'wb'))

```

The file with the ciphertext, IV and leak can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2021/inctf2021/rightNowGenerator/enc.pickle" target="_blank">here</a>.




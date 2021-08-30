---
layout: page
title: Fword 2021 CTF Writeup
---
<hr/>

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/logo.png)

Originally I wasn't planning to play any CTF during this weekend but Diamondroxxx asked me if I could as he and the other members of Social Engineering Experts were participating in <a href="https://angmar2722.github.io/CTFwriteups/2021/yauza2021/" target="_blank">Yauza CTF 2021</a>, a Soviet themed CTF. Me and Diamondroxxx solved all the crypto challenges in Yauza in a few hours so we decided to check if there was some CTF going on. 

Turns out Fword, the top CTF team from Tunisia, was hosting their own <a href="https://ctftime.org/event/1405" target="_blank">Fword CTF 2021</a> and it had some crypto challenges so we decided to play as Isengard as it was only the both of us for that. Sadly we joined late for both CTFs. Fword was only 1 and a half days long and was from Sat, 28 Aug. 2021, 01:00 SGT — Sun, 29 Aug. 2021, 13:00 SGT and we only joined at around 4pm on Saturday. We tried to solve as many crypto challenges as we could until 3 am (we were stuck on the Ed25519 curve challenge). We ranked 55<sup>th</sup> out of 428 scoring teams, focusing only on the crypto challenges.

Solved challenges stats :

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/img2.png)

Timestamps of the challenges we solved :

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/img3.png)


We managed to solve 4 out of the 6 crypto challenges :

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/img1.png)

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Login](#login) | Crypto | 991 | 11 | 
|[Invincible](#invincible) | Crypto | 930 | 28 | 
|[Boombastic](#boombastic) | Crypto | 738 | 54 | 
|[Leaky Blinders](#leaky-blinders) | Crypto | 100 | 120 | 
|[Welcome](#welcome) | Welcome | 10 | 369 | 

<br/>

<br/>

## Login

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/img4.png)

The server source code provided :

```python

#!/usr/bin/env python3.8
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, getPrime, GCD
import os, hashlib, sys, signal
from time import time
                 
FLAG = "FwordCTF{####################################################################}"

WELCOME = '''
Welcome to CTFCreators Website.
We are a challenges development startup from a team of cybersecurity professionals with diverse backgrounds and skills.'''

server_token = os.urandom(16)
message_to_sign = b"https://twitter.com/CTFCreators"


def H(msg):
    return hashlib.sha256(msg).digest()


def gen_key():
    while True:
        p, q = getPrime(1024), getPrime(1024)
        N = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            break
    d = inverse(e, phi)
    pinv = inverse(p, q)
    return N, e, d, pinv


def verify(signature, e, N):
    try:
        signature = int(signature, 16)
        msg = bytes_to_long(message_to_sign)
        verified = pow(signature, e, N)

        if (verified == msg):
            return True
        else:
            return False
    except:
        return False


def sign_up():
    user = str(input("\nUsername : ")).encode()
    proof = b'is_admin=false'
    passwd = H(server_token + b';' + user + b';' + proof)
    return user.hex(), proof.hex(), passwd.hex()


def log_in(username, proof, password):
    if password == H(server_token + b';' + username + b';' + proof):
        if b'is_admin=true' in proof:
            return True
    return False


class Login:
    def __init__(self):
        print(WELCOME)

    def start(self):
        try:
            while True:
                print("\n1- Sign up")
                print("2- Login")
                print("3- Leave")
                c = input("> ")

                if c == '1':
                    usr, prf, pwd = sign_up()
                    print(f"\nAccount created.\nUsername : {usr}\nPassword : {pwd}\nProof : {prf}")

                elif c == '2':
                    user = bytes.fromhex(input("\nUsername : "))
                    passwd = bytes.fromhex(input("Password : "))
                    proof = bytes.fromhex(input("Proof : "))

                    if log_in(user, proof, passwd):
                        N, e, d, pinv = gen_key()
                        print(f"Welcome admin, to continue you need to sign this message : '{message_to_sign}'")
                        print(f"e : {hex(e)}")
                        print(f"d : {hex(d)}")
                        print(f"inverse(p, q) : {hex(pinv)}")

                        sig = input("Enter your signature : ")

                        if verify(sig, e, N):
                            print(f"Long time no see. Here is your flag : {FLAG}")
                        else:
                            sys.exit("Disconnect.")
                    else:
                        sys.exit("Username or password is incorrect.")

                elif c == '3':
                    sys.exit("Goodbye :)")

        except Exception as e:
            print(e)
            sys.exit("System error.")


signal.alarm(60)
if __name__ == "__main__":
    challenge = Login()
    challenge.start()
    
```

While one may be tempted to straight away think that the main goal of the challenge is to somehow create a valid signature where the cryptosystem used is some form of RSA, you first have to login (hence the challenge name). Choosing option 1 allows you to enter a username. After that using the function `sign_up()`, a password <i>P</i> is generated which is a SHA-256 hash (H) of a server token <i>st</i> (16 random and unknown secret bytes) followed by the entered username and then a proof set to `is_admin=false` such that :

<p align="center"> Password = H(st + user + proof) </p>

After an 'account' is created, the password (the hash), entered username and current proof is provided to us. Now if we want to login using option 2, we are prompted to enter a username, a password and proof. This is then checked using the function `log_in`. Over here we have to ensure that the password that we provided (a SHA-256 hash) matches the hash of the 16 unknown server token bytes along with the provided username and a proof set to `is_admin=true`. Obviously the hash that we got from option 1 is incorrect because the proof had admin set to false not true. Since we don't know the 16 secret server token bytes, we cannot compute a hash ourselves and obviously it is impossible to reverse SHA-256. Eventually after some reading, we came across something known as a <a href="https://en.wikipedia.org/wiki/Length_extension_attack" target="_blank">Hash Length Extension Attack</a>.

In a hash length extension attack, if one knows the hash (H) of a message appended to some secret key, so known = H(sk + m), where only the messagea and the length of the secret key is known, one can calculate the hash of the secret key followed by the known message with some padding followed by a desired final message. Hence we can compute a valid hash for logging in without ever knowing the 16 secret server token bytes such that :

<p align="center"> Entered Password = H(st + user + padding (length extension) + proof) </p>

where the username we input in option 2 is user+padding and the proof is set to `is_admin=true`. We used <a href="https://github.com/stephenbradshaw/hlextend" target="_blank">this Python hash extender</a> in order to calculate the extension. After logging in, we are then given some of the parameters of the RSA cryptosystem - the public exponent (e) and curiously the private key (d) along with the result of the modular multiplicative inverse of the prime `p` with respect to `q`. Most notably, we are not given the public modulus `N`. 

Our goal is to generate a valid signature for the message `https://twitter.com/CTFCreators` where our signature is validated by the server using the `verify` method. Looking at the verification function, we can clearly see from the line `verified = pow(signature, e, N)` that verification is analogous to the encryption of a message in RSA as ciphertext = pow(m, e, N). So our signature should be the same as the decryption of a message for RSA so signature = pow(m, d, N). Note that this is how signatures are generated using RSA and the vulnerability is obviously that the private key `d` is provided to us.

It still isn't straightforward to generate the signature as we don't have the modulus `N` yet. Somehow, using the private key, public exponent and the modular inverse of p with respect to q, we had to derive N after which we can sign the message and get the flag. After some reading, we realized that <a href="https://gist.github.com/n-ari/a2db9af7fd3c172e4fa65b923a66beff" target="_blank">this writeup</a> contained the solution, the explanation being summarised below :

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/img12.png)

One thing to note is that in the writeup, the range of possible k values where `(ed-1)*e / k == (p-1)*(q-1)` traversed was from 1 to 100,000 but in reality, the possible values of k would not exceed the public exponent e = 65537.

Our solve script :

```python
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, getPrime, GCD
import os, hashlib, sys, signal
from math import gcd
from sympy import isprime
from re import match
from math import ceil

local = False
debug = True

if local:
    r = process(["python3", "local.py"], level='debug') if debug else process(["python3", "local.py"])
else:
    r = remote("52.149.135.130", 4871, level = 'debug') if debug else remote("52.149.135.130", 4871)


r.sendlineafter('> ', b'1')

user = b'hi'
r.sendlineafter('Username : ', user)
r.recvuntil(b'Account created.\n')

username = r.recvline()[11:].decode().strip()
password = r.recvline()[11:].decode().strip()
proof = r.recvline()[8:].decode().strip()


#https://github.com/stephenbradshaw/hlextend
class Hash(object):
    '''Parent class for hash functions'''


    def hash(self, message):
        '''Normal input for data into hash function'''

        length = bin(len(message) * 8)[2:].rjust(self._blockSize, "0")
        
        while len(message) > self._blockSize:            
            self._transform(''.join([bin(ord(a))[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        message = self.__hashBinaryPad(message, length)
        

        for a in range(len(message) // self._b2):
            self._transform(message[a * self._b2:a * self._b2 + self._b2])



    def extend(self, appendData, knownData, secretLength, startHash, raw=False):
        '''Hash length extension input for data into hash function'''

        self.__checkInput(secretLength, startHash)
        self.__setStartingHash(startHash)        
        
        extendLength = self.__hashGetExtendLength(secretLength, knownData, appendData)        

        message = appendData

        while len(message) > self._blockSize:
            self._transform(''.join([bin(ord(a))[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        message = self.__hashBinaryPad(message, extendLength)        

        for i in range(len(message) // self._b2):
            self._transform(message[i * self._b2:i * self._b2 + self._b2])

        return self.__hashGetPadData(secretLength, knownData, appendData, raw=raw)


    def hexdigest(self):
        '''Outputs hash data in hexlified format'''
        return ''.join( [ (('%0' + str(self._b1) + 'x') % (a)) for a in self.__digest()])


    def __init__(self):
        # pre calculate some values that get used a lot
        self._b1 = self._blockSize/8
        self._b2 = self._blockSize*8



    def __digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]


    def __setStartingHash(self, startHash):
        c = 0
        hashVals = [ int(startHash[a:a+int(self._b1)],base=16) for a in range(0,len(startHash), int(self._b1)) ]
        for hv in [ a for a in dir(self) if match('^_h\d+$', a) ]:
            self.__setattr__(hv, hashVals[c])        
            c+=1


    def __checkInput(self, secretLength, startHash):
        if not isinstance(secretLength, int):
            raise TypeError('secretLength must be a valid integer')
        if secretLength < 1:
            raise ValueError('secretLength must be grater than 0')
        if not match('^[a-fA-F0-9]{' + str(len(self.hexdigest())) + '}$', startHash):
            raise ValueError('startHash must be a string of length ' + str(len(self.hexdigest())) + ' in hexlified format')
        

    def __byter(self, byteVal):
        '''Helper function to return usable values for hash extension append data'''
        if byteVal < 0x20 or byteVal > 0x7e:
            return '\\x%02x' %(byteVal)
        else:    
            return chr(byteVal)


    def __binToByte(self, binary):
        '''Convert a binary string to a byte string'''
        return ''.join([ chr(int(binary[a:a+8],base=2)) for a in range(0,len(binary),8) ])



    def __hashGetExtendLength(self, secretLength, knownData, appendData):
        '''Length function for hash length extension attacks'''
        # binary length (secretLength + len(knownData) + size of binarysize+1) rounded to a multiple of blockSize + length of appended data
        originalHashLength = int(ceil((secretLength+len(knownData)+self._b1+1)/float(self._blockSize)) * self._blockSize) 
        newHashLength = originalHashLength + len(appendData) 
        return bin(newHashLength * 8)[2:].rjust(self._blockSize, "0")


    def __hashGetPadData(self, secretLength, knownData, appendData, raw=False):
        '''Return append value for hash extension attack'''    
        originalHashLength = bin((secretLength+len(knownData)) * 8)[2:].rjust(self._blockSize, "0")    
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in knownData) + "1"
        padData += "0" * (((self._blockSize*7) - (len(padData)+(secretLength*8)) % self._b2) % self._b2) + originalHashLength 
        if not raw:
            return ''.join([ self.__byter(int(padData[a:a+8],base=2)) for a in range(0,len(padData),8) ]) + appendData
        else:
            return self.__binToByte(padData) + appendData    


    def __hashBinaryPad(self, message, length):
        '''Pads the final blockSize block with \x80, zeros, and the length, converts to binary'''
        message = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in message) + "1"    
        message += "0" * (((self._blockSize*7) - len(message) % self._b2) % self._b2) + length
        return message


class SHA256 (Hash):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    _blockSize = 64


    def _transform(self, chunk):
        rrot = lambda x, n: (x >> n) | (x << (32 - n))
        w = []

        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~ e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
        self._h5 = (self._h5 + f) & 0xffffffff
        self._h6 = (self._h6 + g) & 0xffffffff
        self._h7 = (self._h7 + h) & 0xffffffff


def new(algorithm):
    obj = {
        'sha256': SHA256,
    }[algorithm]()
    return obj


def sha256():
    ''' Returns a new sha256 hash object '''
    return new('sha256', )


sha = new('sha256')
extension = sha.extend(';is_admin=true', ';hi;is_admin=false', 16, password)[1:-14]

r.sendlineafter('> ', b'2')
r.sendlineafter('Username : ', eval(f"b'{extension}'").hex())
passwdPayload = sha.hexdigest()
r.sendlineafter('Password : ', passwdPayload.encode())
proofPayload = b'is_admin=true'
r.sendlineafter('Proof : ', proofPayload.hex().encode())

print(r.recvline())

e = int(r.recvline()[4:].decode().strip(), 16)
d = int(r.recvline()[4:].decode().strip(), 16)
inversePQ = int(r.recvline()[16:].decode().strip(), 16)


upper_lim = min(e, d)
ks = []

for k in range(2, upper_lim):
	if (e * d - 1) % k == 0 and ((e * d - 1) // k).bit_length() <= 2048:
		ks.append(k)

# print("[*] Possible number of k values = ", len(ks)) # 1
print(f"List of possible Ks = {ks}")

for k in ks:
    print(f"K checked is {k}")
    phi = (e*d - 1) // k
    c1 = (phi - 1) * inversePQ + 1
    
    factors = [c1]
    for i in range(2, 11):
        factors.append(pow(i, phi, c1) - 1)
    q = gcd(*factors)

    if q.bit_length() != 1024 or not isprime(q): continue
    print(f"q : {q} and isprime = {isprime(q)}")

    p = phi // (q - 1) + 1
    if d != inverse(e, (p-1)*(q-1)) or p.bit_length() != 1024 or not isprime(p): continue
    print(f"p : {p} and isprime = {isprime(p)}")

    if inversePQ != inverse(p, q) : continue
    break


n = p*q
print(n)
message_to_sign = b"https://twitter.com/CTFCreators"
payload = hex(pow(bytes_to_long(message_to_sign), d, int(n)))[2:]

r.sendlineafter('Enter your signature : ', payload)
print(r.recvline())

```

And after running the script, we can see that the possible values of phi are selected and after reconstructing the modulus and hence the signature, we got the flag :

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/img5.png)

<p> <b>Flag :</b> FwordCTF{N3v3r_judg3_s0m3th1ng_y0u_kn0w_n0thing_4b0ut_3sp3c14lly_pr1v4t3_k3ys} </p>






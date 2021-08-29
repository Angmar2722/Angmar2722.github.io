---
layout: page
title: Fword 2021 CTF Writeup
---
<hr/>

![Fword CTF 2021 Writeup](/assets/img/ctfImages/2021/fword2021/logo.png)

Originally I wasn't planning to play any CTF during this weekend but Diamondroxxx asked me if I could as he and the other members of Social Engineering Experts were participating in <a href="https://ctftime.org/event/1417" target="_blank">Yauza CTF 2021</a>, a Soviet themed CTF. Me and Diamondroxxx solved all the crypto challenges in Yauza in a few hours so we decided to check if there was some CTF going on. 

Turns out the top CTF team from Tunisia Fword was hosting their own CTF <a href="https://ctftime.org/event/1405" target="_blank">Fword CTF 2021</a> and it had some crypto challenges so we decided to play as Isengard as it was only the both of us for that. Sadly we joined late for both CTFs. Fword was only 1 and a half days long and was from Sat, 28 Aug. 2021, 01:00 SGT — Sun, 29 Aug. 2021, 13:00 SGT and we only joined at around 4pm on Saturday. We tried to solve as many crypto challenges as we could until 3 am (we were stuck on the Ed25519 curve challenge). We ranked 55<sup>th</sup> out of 428 scoring teams, focusing only on the crypto challenges.

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



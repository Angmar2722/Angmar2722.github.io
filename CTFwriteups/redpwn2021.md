---
layout: page
title: Redpwn 2021 CTF Writeup
---
<hr/>

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/logo.png)

Me and Diamondroxxx competed as the two man CTF team "Isengard" in the <a href="https://ctftime.org/event/1327" target="_blank">Redpwn 2021 CTF</a> event (Sat, 10 July 2021, 03:00 SGT — Tue, 13 July 2021, 03:00 SGT). We got up at 3 am since thats when it started and the CTF lasted for 3 days. We ranked 41st out of 1418 scoring teams and once again, this was our best CTF performance yet. 

I managed to solve 18 challenges and once again, a lot of these challenges were solved by collaborating closely with Diamondroxxx. Overall it was a great time and as with nearly every CTF, it was a great learning experience. We solved 8 out of the 9 cryptography challenges and the one we couldn't solve - "quaternion-revenge" was a 'troll' challenge, more on that towards the end of the writeup. I also managed to solve at least one challenge from every category.

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Retrosign](#retrosign) | Crypto | 216 | 26 | 
|[Keeper-of-the-Flag](#keeper-of-the-flag) | Crypto | 174 | 42 |
|[Scrambled-Elgs](#scrambled-elgs) | Crypto | 143 | 70 |
|[Yahtzee](#yahtzee) | Crypto | 128 | 103 |
|[Blecc](#blecc) | Crypto | 119 | 146 |
|[Ret2the-Unknown](#ret2the-unknown) | Pwn | 108 | 288 |
|[Bread-Making](#bread-making) | Rev | 108 | 317 |
|[Round-The-Bases](#round-the-bases) | Crypto | 107 | 348 |
|[Printf-Please](#printf-please) | Pwn | 107 | 353 |
|[Ret2generic-Flag-Reader](#ret2generic-flag-reader) | Pwn | 105 | 465 |
|[Beginner-Generic-Pwn-Number-0](#beginner-generic-pwn-number-0) | Pwn | 105 | 485 |
|[Baby](#baby) | Crypto | 102 | 827 |
|[Wstrings](#wstrings) | Rev | 102 | 844 |
|[Scissor](#scissor) | Crypto | 102 | 1005 |
|[Inspect-Me](#inspect-me) | Web | 101 | 1291 |
|[Survey](#survey) | Misc | 1 | 268 |
|[Discord](#discord) | Misc | 1 | 971 |
|[Sanity-Check](#sanity-check) | Misc | 1 | 1329 |

<br/>

<br/>

## Retrosign

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img2.png)

Source Code provided :

```python

#!/usr/local/bin/python

from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Hash import SHA256
from binascii import unhexlify
from secrets import randbelow

with open('flag.txt','r') as f:
    flag = f.read().strip()

def sha256(val):
    h = SHA256.new()
    h.update(val)
    return h.digest()

def execute(cmd):
    if cmd == "sice_deets":
        print(flag)
    elif cmd == "bad_signature":
        print("INTRUSION DETECTED!")
    else:
        print("Command unknown.")

def authorize_command(cmd, sig):
    assert len(sig) == 128*2
    a = bytes_to_long(sig[:128])
    b = bytes_to_long(sig[128:])
    if (a**2 + k*b**2) % n == bytes_to_long(sha256(cmd)):
        execute(cmd.decode())
    else:
        execute("bad_signature")

p = getPrime(512)
q = getPrime(512)
n = p * q
k = randbelow(n)
def interact():
    print("===============================================================================")
    print("This mainframe is protected with state-of-the-art intrusion detection software.")
    print("All commands are passed through a signature-based filter.")
    print("===============================================================================")
    print("The following configuration is in place:")
    print(f"n = {n};\nk = {k};")
    print("Server configured.")
    cmd = input(">>> ").strip().lower().encode()
    sig = unhexlify(input("$$$ "))
    authorize_command(cmd, sig)
    print("Connection closed.")

if __name__ == "__main__":
    try:
        interact()
    except:
        print("An error has occurred.")

```

When you first connect to the server, you had to run a proof of work. After that, a 1024 bit modulus `n` (a product of two 512 bit primes) is provided along with a random number `k` which is smaller than n. After that, we are expected to provide two inputs, `cmd` which is in bytes and `sig` which is in hex. The main challenge is shown in the function `authorize_command`. 

Over here, the server first checks whether the length of sig is 256 bytes and assigns the lower 128 bytes to `a` and the upper 128 bytes to `sig` to `b`. It then checks whether the following bivariate equation holds true :

\\(\{a^2 + k*b^2} mod n = h(cmd)\\)

So the integer hash of `cmd` has to equal the left hand side, a squared plus b squared times k the whole mod n. That seems really hard to do since we are dealing with modular arithmetic and two variables. Also of note, if we successfully meet this condition, the server then checks whether `cmd` equals the string `"sice_deets"` which immediatly tells us that that our input for cmd has to be "sice_deets" and nothing else. So how do we go about beating this condition????

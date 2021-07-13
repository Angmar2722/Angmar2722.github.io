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

When you first connect to the server, you had to run a proof of work. After that, a 1024 bit modulus `n` (a product of two 512 bit primes) is provided along with a random number `k` which is smaller than n. After that, we are expected to provide two inputs, `cmd` which is in bytes and `sig` which is in hex. The main challenge is shown in the function "authorize_command". 

Over here, the server first checks whether the length of sig is 256 bytes and assigns the lower 128 bytes to `a` and the upper 128 bytes of sig to `b`. It then checks whether the following bivariate equation holds true :

\\((a^2 + kb^2) \ mod \ n = h(cmd)\\)

So the integer hash of cmd, `h(cmd)`, has to equal the left hand side, a squared plus b squared times k the whole mod n. That seems really hard to do since we are dealing with modular arithmetic and two variables. We control the value of a and b (as it is based on our input in sig) but the server assigns a random n and k. Also of note, if we successfully meet this condition, the server then checks whether cmd equals the string `"sice_deets"` which immediatly tells us that that our input for cmd has to be "sice_deets" and nothing else. So how do we go about beating this condition????

I spent so many hours going in different tangents with regards to solving this challenge. Eventually, I came across this relatively obscure identification and signature system known as the <a href="https://sci-hub.do/10.1145/800057.808683" target="_blank">Ong-Schnorr-Shamir signature system</a> or OSS for short. The method of verifying if a signature was valid was more or less perfectly analogous to the bivariate equation shown above. This scheme was introduced in 184 and hence fit the theme of the challenge name "retrosign". This looked promising.

Turns out there is a <a href="https://sci-hub.do/10.1109/tit.1987.1057350" target="_blank">1987 research paper</a> which is literally called "An Efficient Solution of the Congruence \\((x^2 + ky^2) = m \ mod \ n \\)" which was exactly what we needed. The authors, John M. Pollard and Claus P. Schnorr had created an algorithm which finds the solutions to this equation. In fact, someone had even implemented this algorithm in a past CTF in <a href="https://abeaumont.me/posts/OSS-Service-Hard-crypto-500.html" target="_blank">this writeup</a>. After implementing that algorithm, finding the correct values of a and b was a breeze. With that we made our solve script and got the flag.

Our Sage solve script :

```python

from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Hash import SHA256
from binascii import unhexlify
from secrets import randbelow
from pwn import *

def sha256(val):
    h = SHA256.new()
    h.update(val)
    return h.digest()

def mult(x1, y1, x2, y2, k):
    """(x1^2 + ky^1)(x^2 + ky^2)"""
    return (x1 * x2 + k*y1*y2) % n, (x1 * y2 - y1 * x2) % n

def pollard(k, m):
    # Generate a valid prime m0 < m and x0
    while True:
        while True:
            u = randrange(n)
            v = randrange(n)
            m0 = m*(u*u+k*v*v)%n
            if m0 % 4 == 3: break
        x0 = pow(-k, (m0 + 1)/4, m0)
        if pow(x0, 2, m0) == -k % m0:
            break
    xx = [0,Integer(x0)]
    mm = [0,m0]

    # Generate the series x_i, m_i, till m_I
    while not (xx[-2] <= mm[-1] <= mm[-2]):
        mm.append((xx[-1] * xx[-1] + k) / mm[-1] % n)
        xx.append(min(xx[-1] % mm[-1], (mm[-1] - xx[-1]) % mm[-1]) % n)

    # Multiply all the equations to get s0, t0
    s, t = xx[1], 1
    for x in xx[2:-1]:
        s, t = s * x-k * t, s + x*t

    # Get s1, t1 from s0, t0
    M = mul(mm[2:]) % n
    s1 = s * inverse_mod(M, n) % n
    t1 = t * inverse_mod(M, n) % n

    # Get s2, t2 either trivially or recursivelly
    if is_square(mm[-1]):
        s2, t2 = sqrt(mm[-1]), 0
    elif mm[-1] == k:
        s2, t2 = 0, 1
    else:
        # Change variables and solve recursively
        s22, t22 = pollard(Integer(-mm[-1]), -k)
        # Change variables back
        t2 = inverse_mod(t22, n)
        s2 = s22 * t2

    # Get s4, t4 multiplying previous solutions
    s3, t3 = mult(u, v, s1, t1, k)
    s4, t4 = mult(s3, t3, s2, t2, k)

    # Obtain the solution to the original problem
    m0inv = inverse_mod(Integer(m0), n)
    return s4 * m * m0inv % n, t4 * m * m0inv % n

local = False
debug = True

if local:
    r = process(["python3", "server.py"], level='debug') if debug else process(["python3", "server.py"])
else:
    r = remote("mc.ax", 31079, level = 'debug') if debug else remote("mc.ax", 31538)
    r.recvuntil("proof of work: ")
    proof_of_work = r.recvline(keepends=False).decode()
    print(f"{proof_of_work=}")
    ans = os.popen(proof_of_work).read()
    r.sendafter("solution: ", ans)

r.recvuntil("The following configuration is in place:\n")

n = r.recvline()
n = Integer(n[4:-2].decode())

k = r.recvline()
k = Integer(k[4:-2].decode())

signature = bytes_to_long(sha256(b"sice_deets"))

x, y = pollard(k, signature)
payload = hex(x)[2:]+hex(y)[2:]

r.sendlineafter(">>> ", "sice_deets")
r.sendlineafter("$$$ ", payload)
print(r.recvall())

```

And after running this script, we got the flag :

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img3.png)

Curiously, our script kept crashing when we weren't in debug mode (this is from Pwntools) for some reason so thats why we had to use that to get the flag. Also I was super happy that I found this signature system in a timely manner - 2 hours before the CTF ended.

<p> <b>Flag :</b> flag{w0w_th4t_s1gn4tur3_w4s_pr3tty_r3tr0} </p>

<br/>

## Keeper-of-the-Flag

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img4.png)

The source code provided :

```python

#!/usr/local/bin/python3

from Crypto.Util.number import *
from Crypto.PublicKey import DSA
from random import *
from hashlib import sha1

rot = randint(2, 2 ** 160 - 1)
chop = getPrime(159)

def H(s):
    x = bytes_to_long(sha1(s).digest())
    return pow(x, rot, chop)


L, N = 1024, 160
dsakey = DSA.generate(1024)
p = dsakey.p
q = dsakey.q
h = randint(2, p - 2)
g = pow(h, (p - 1) // q, p)
if g == 1:
    print("oops")
    exit(1)

print(p)
print(q)
print(g)

x = randint(1, q - 1)
y = pow(g, x, p)

print(y)


def verify(r, s, m):
    if not (0 < r and r < q and 0 < s and s < q):
        return False
    w = pow(s, q - 2, q)
    u1 = (H(m) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r


pad = randint(1, 2 ** 160)
signed = []
for i in range(2):
    print("what would you like me to sign? in hex, please")
    m = bytes.fromhex(input())
    if m == b'give flag' or m == b'give me all your money':
        print("haha nice try...")
        exit()
    if m in signed:
        print("i already signed that!")
        exit()
    signed.append(m)
    k = (H(m) + pad + i) % q
    if k < 1:
        exit()
    r = pow(g, k, p) % q
    if r == 0:
        exit()
    s = (pow(k, q - 2, q) * (H(m) + x * r)) % q
    if s == 0:
        exit()
    print(H(m))
    print(r)
    print(s)

print("ok im done for now")
print("you visit the flag keeper...")
print("for flag, you must bring me signed message:")
print("'give flag':" + str(H(b"give flag")))

r1 = int(input())
s1 = int(input())
if verify(r1, s1, b"give flag"):
    print(open("flag.txt").readline())
else:
    print("sorry")

```

Once again when you first connect to the server, you had to solve the proof of work. The signature algorithm in this challenge was the <a href="https://en.wikipedia.org/wiki/Digital_Signature_Algorithm" target="_blank">Digital Signature Algorithm (DSA)</a>. The public key consists of the parameters `p, q, g, y` which is provided to us and the private key is `x`. When signing a message, you have to first choose a random integer `k` which is between 1 and (q-1). After that, the signature (r, s) is calculated by the following equations :

\\(r = ( \ g^k \ mod \ p ) \ mod \ q\\)

\\(s = (k^{-1} \ (H(m) + xr)) \ mod \ q\\)

As shown in the server code above, the aim of this challenge was to compute the correct signature for the string "give flag". The server would sign any 2 messages for us. The catch was that we obviously couldn't get the signature for "give flag", that was blacklisted, and also we couldn't get the signature for the same message twice as if we could, it <a href="https://wiki.x10sec.org/crypto/signature/dsa/#principle" target="_blank">would be trivial</a> to recover the random number `k` and hence the private key `x`.

The calculations for computing r, s and the verification of a signature in the function `verify(r, s, m)` seem to be correct so what is the vulnerability in the code shown above? Remember that k has to be a random number between 1 and (q-1) but over here, `k = (H(m) + pad + i) % q`. Hmmm, that seems rather odd, there is a custom implementation for generating k so surely there must be a flaw in this implementation?

Turns out that is the case as pointed out by <a href="https://crypto.stackexchange.com/questions/7904/attack-on-dsa-with-signatures-made-with-k-k1-k2" target="_blank">this thread</a> where a vulnerability is discussed when two consecutive random numbers, k and k + 1 are chosen. With that implementation, as answered in the thread, by using Gaussian elimination, the value of the random number `k` can be calculated. 

The trick to getting two consecutive values of k (k and k+1) was making sure that the hash of our messages, `H(m)`, were equal. Since the value of pad was declared outside the loop, it would have a constant value for both signatures. Similarly, if the values of the hash were equal (for two different messages), this would effectively be a constant value added to the value of the iteration in the loop. This means that it would be some constant mod q for the first signature and some constant plus one the whole mod q for the second signature hence having two consecutive values of k (as it would be more or less improbable for the second value to wrap around the modulus q one more time than the first one).

To get two different messages with the same hash, we had to find an instance of a SHA-1 collision which we got from <a href="https://shattered.io/" target="_blank">this website</a> (this was a <a href="https://techcrunch.com/2017/02/23/security-researchers-announce-first-practical-sha-1-collision-attack/" target="_blank">very big breakthrough</a> in 2017).

With that, the private key `x` can also be recovered. We used the equations shown in that thread to recover k but it didn't work for `x` so instead after finding k, we used the equation `x = ((s * k - h) * rinv) % q` from <a href="https://github.com/AdityaVallabh/ctf-write-ups/blob/master/CSAW%20Finals%202018/Disastrous%20Security%20Apparatus/README.md" target="_blank">this writeup</a> to recover the private key.

After getting x and k, we could sign "give_flag" ourselves as we had all the paramters used for signing a message and we could pass that to the server and with that, we got the flag.

Our Sage solve script :

```python

from pwn import *
from Crypto.Util.number import *
import os

local = False
debug = False

if local:
    r = process(["python3", "kotf.py"], level='debug') if debug else process(["python3", "kotf.py"])
else:
    r = remote("mc.ax", 31538, level = 'debug') if debug else remote("mc.ax", 31538)
    r.recvuntil("proof of work: ")
    proof_of_work = r.recvline(keepends=False).decode()
    print(f"{proof_of_work=}")
    ans = os.popen(proof_of_work).read()
    r.sendafter("solution: ", ans)

p = Integer(r.recvline(keepends=False).decode())
q = Integer(r.recvline(keepends=False).decode())
g = Integer(r.recvline(keepends=False).decode())
y = Integer(r.recvline(keepends=False).decode())
print(f"{p=}\n{q=}\n{g=}\n{y=}")

import urllib.request
res = urllib.request.urlopen('http://shattered.io/static/shattered-1.pdf')
m1 = res.read().hex()
res = urllib.request.urlopen('http://shattered.io/static/shattered-2.pdf')
m2 = res.read().hex()

r.recvuntil("what would you like me to sign? in hex, please\n")
r.sendline(m1)

h1 = Integer(r.recvline(keepends=False).decode())
r1 = Integer(r.recvline(keepends=False).decode())
s1 = Integer(r.recvline(keepends=False).decode())
print(f"{h1=}\n{r1=}\n{s1=}")

r.recvuntil("what would you like me to sign? in hex, please\n")
r.sendline(m2)

h2 = Integer(r.recvline(keepends=False).decode())
r2 = Integer(r.recvline(keepends=False).decode())
s2 = Integer(r.recvline(keepends=False).decode())
print(f"{h2=}\n{r1=}\n{s1=}")

# Formula gotten from
# https://crypto.stackexchange.com/questions/7904/attack-on-dsa-with-signatures-made-with-k-k1-k2
k = ((h2 - s2 - (h1 * r2 / r1))//(s2 - (s1 * r2 / r1))) % q
# Formula for x gotten from
# https://github.com/AdityaVallabh/ctf-write-ups/blob/master/CSAW%20Finals%202018/Disastrous%20Security%20Apparatus/README.md
x = ((s1 * k - h1) * inverse(r1, q)) % q

print(f"{k=}\n{x=}")
r.recvuntil("'give flag':")
hashedGiveFlag = Integer(r.recvline(keepends=False).decode())
print(f"{hashedGiveFlag=}")

# Sign "Give Flag"
while True:
    R = int(pow(g, k, p)) % int(q)
    if R == 0:
        continue
    S = (pow(k, q - 2, q) * (hashedGiveFlag + x * R)) % q
    if S == 0:
        continue
    break

outputR = str(R).encode()
outputS = str(S).encode()
r.sendline(outputR)
r.sendline(outputS)

print(r.recvall())

```
And after running the script, we got the flag :
 
![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img5.png)

<p> <b>Flag :</b> flag{here_it_is_a8036d2f57ec7cecf8acc2fe6d330a71} </p>

<br/>

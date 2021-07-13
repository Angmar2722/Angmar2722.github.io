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

The trick to getting two consecutive values of k (k and k+1) was making sure that the hash of our messages, `H(m)`, were equal. Since the value of `pad` was declared outside the loop, it would have a constant value for both signatures. Similarly, if the values of the hash were equal (for two different messages), this would effectively be a constant value added to the value of the iteration in the loop. This means that it would be some constant mod q for the first signature and some constant plus one the whole mod q for the second signature hence having two consecutive values of k (as it would be more or less improbable for the second value to wrap around the modulus q one more time than the first one).

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

## Scrambled-Elgs

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img6.png)

The Sage code provided :

```python

#!/usr/bin/env sage
import secrets
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.combinat import permutation

n = 25_000
Sn = SymmetricGroup(n)

def pad(M):
    padding = long_to_bytes(secrets.randbelow(factorial(n)))
    padded = padding[:-len(M)] + M
    return bytes_to_long(padded)

#Prepare the flag
with open('flag.txt','r') as flag:
    M = flag.read().strip().encode()
m = Sn(permutation.from_rank(n,pad(M)))

#Scramble the elgs
g = Sn.random_element()
a = secrets.randbelow(int(g.order()))
h = g^a
pub = (g, h)

#Encrypt using scrambled elgs
g, h = pub
k = secrets.randbelow(n)
t1 = g^k
t2 = m*h^k
ct = (t1,t2)

#Provide public key and ciphertext
with open('output.json','w') as f:
	json.dump({'g':str(g),'h':str(h),'t1':str(t1),'t2':str(t2)}, f)

```

This is a <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/redpwn2021/output.json" target="_blank">link</a> to the output.json file which was provided.

The method of encryption looks really weird with Sage functions like Symmetric Groups and permutations from rank. Since `n` was below 25,000, we could bruteforce the value of `k`. After that, by playing around with similar Sage functions, we found a way to retrieve the flag, by using Permutation.rank().

Our Sage solve script :

```python

import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.combinat import permutation

output = json.load(open('output.json', 'r'))
n = 25_000
Sn = SymmetricGroup(n)

g = Sn(output["g"])
h = Sn(output["h"])

t1 = Sn(output["t1"])
t2 = Sn(output["t2"])

for k in range(n):
    if (g^k == t1):
        break

m = t2/(h^k)
flag = long_to_bytes( Permutation(m).rank() )
print(flag[-50:])

```
<p> <b>Flag :</b> flag{1_w1ll_n0t_34t_th3m_s4m_1_4m} </p>

<br/>

## Yahtzee

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img7.png)

The server code provided :

```python

#!/usr/local/bin/python

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from random import randint
from binascii import hexlify

with open('flag.txt','r') as f:
    flag = f.read().strip()

with open('keyfile','rb') as f:
    key = f.read()
    assert len(key)==32

'''
Pseudorandom number generators are weak!
True randomness comes from phyisical objects, like dice!
'''
class TrueRNG:

    @staticmethod
    def die():
        return randint(1, 6)

    @staticmethod
    def yahtzee(N):
        dice = [TrueRNG.die() for n in range(N)]
        return sum(dice)

    def __init__(self, num_dice):
        self.rolls = num_dice

    def next(self):
        return TrueRNG.yahtzee(self.rolls)

def encrypt(message, key, true_rng):
    nonce = true_rng.next()
    cipher = AES.new(key, AES.MODE_CTR, nonce = long_to_bytes(nonce))
    return cipher.encrypt(message)

'''
Stick the flag in a random quote!
'''
def random_message():
    NUM_QUOTES = 25
    quote_idx = randint(0,NUM_QUOTES-1)
    with open('quotes.txt','r') as f:
        for idx, line in enumerate(f):
            if idx == quote_idx:
                quote = line.strip().split()
                break
    quote.insert(randint(0, len(quote)), flag)
    return ' '.join(quote)

banner = '''
============================================================================
=            Welcome to the yahtzee message encryption service.            =
=  We use top-of-the-line TRUE random number generators... dice in a cup!  =
============================================================================
Would you like some samples?
'''
prompt = "Would you like some more samples, or are you ready to 'quit'?\n"

if __name__ == '__main__':
    NUM_DICE = 2
    true_rng = TrueRNG(NUM_DICE)
    inp      = input(banner)
    while 'quit' not in inp.lower():
        message = random_message().encode()
        encrypted = encrypt(message, key, true_rng)
        print('Ciphertext:', hexlify(encrypted).decode())
        inp = input(prompt)

```

Lets break down the code above. In the function main, the number of dice is set to two. A TrueRNG object is then initialized in the line`true_rng = TrueRNG(NUM_DICE)`. So when we connect to the server, we can request basically as many ciphertexts as we want. A message is created from the function `random_message` where a single random quote is selected from 25 quotes. A flag is then inserted at a random index within the quote and that forms the message. So say the quote chosen was "It is a bright and sunny day". If the random index for the flag to be inserted was at 1, the message would become "It flag{this_is_a_demo} is a bright and sunny day".

This message is then encrypted in a very peculiar way. The key is constant throughout the encryption process for any message. The nonce is constructed via `true_rng.next` where the sum of two random rolls of two dice is outputted. This is then used as a nonce and the message which contains the flag is encrypted using AES CTR mode. So if the two random rolls were 5 and 4, their sum 9 would be used as the inital nonce (the IV) and from there the nonce would be incremented for each block. The image below shows how the CTR mode of operation works :

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img8.png)

Solving this challenge involves exploiting the situation where the nonce and key is repeated. Lets say the encrypted nonce is EN which is repeated. So the ciphertext for message one would be C1 = M1 XOR EN and for message two, the ciphertext would be C2 = M2 XOR EN. If you XOR C1 and C2 this would be C1 XOR C2 = M1 XOR EN XOR M2 XOR EN which is just C1 XOR C2 = M1 XOR M2 as EN XOR EN is 0. So if a nonce is repeated (and so is the key), the XOR of two different messages would equal the XOR of the corresponding two ciphertexts.

So to solve this challenge, we first accumulated **a lot** of different ciphertexts. Since the sum of two dices is used as the nonce, we could only have 11 possible nonce values, from 2 (which is 1 + 1) to 12 (which is 6 + 6). Now assuming that we got a message where the flag was inserted right at the start and assuming we had another different message where the flag was inserted anywhere but at the start, by XORing their ciphertexts with "flag{" which we know is the first 5 bytes of the message with flag at the start, we would get the first 5 bytes of the other message.

If this is slightly confusing, hopefully the code below will demonstrate this :

```python

from pwn import xor

mainList = [b'11ebe5ec559699d0d506b4c259f4a1f70af9b89616c646c5ac63ba933485487f85d7434d4f52d03197d24f429dda2c87d2d801b02f80a149a3216cf306c0bf006f72eb989c8be1c235c365bf70e3d0ee609e4f8bb74694854b39d494', b'6bb61da0fbdb1d066d75b11ee30b1a15d3fe16ae1440dcb4d4be624609eeb43c55b8e05ae0d0f0d764aa056165b5e5fa104c8d700a7a609f97e3707df636f01c0f3b2696c553ef7efeef6a37642f296426b02523b32451938c3f6a2f94304ea7eeffbc959a02d1ffc594095964c3ca4264', b'66b10da0fbd517522f73fe17e7171545d4f006e01040d7e4d1bd62580fedf17a41a1ac02a8d7ecd164a3056320a6b7f64308847306787f8f96da0730a8378f0c08302085c27ef81f81ba68227164697504c7736be70f4d9287263032ac7e7590b8e8e883c51cdca2', b'97dfde725b59c1a4edccf66c9a532a489e6fc9502d69fc743c226e2ab045a741cf47a153ca7d8f128c5d48c8c0714b85ad6c4e407fb00388a0373f618125f26652e6a2e7c652e9e38856d46d01a2c9d70bd7daf8c8c26c251c19d0325c86ec735a39b2819cc832', b'8fce977880973181a12cee8621e6a1f0d46c36180ea6eec67170b48b96bd41c87d1b78513c2a6704e98d5af5f98b1ea2ba9c01427d4c133113b0ab2c243953cb1d48fe29882c92bf26c172c859262f35ababba18ea7987ded68d261e574a4fd5', b'9c144aa898c876a531f639d02aa5d91f994745a1f95be0adb9ce7dc9f4aeb1466504b3525f72300894895b43dd0defc59c642d45e49239d70440d5a3ddcb6318a366603fda19f79c289d78763e49569b7c905edf10618a5c9b89af2ae6b8d7990820637a83b39d56', b'93cab02e90781059681ce0260e2f528cd47b57d54da8e3bfb679e57efd7958035573666064651faadcfcb10cf38e7882bc6093e4f85fdebe961f4444335ff5690159773c76eca1776932b132e4583884da06d4b63e61927651c4fd3d807321b1977dfea619', b'9286932c998a2b97f43ce2c02af6e2f6cd7b750915bca0d53e39b3c38ba61ec852577753317f7d7bd9d81de486991aa6afd442754c547833099bad7431321d982643d21fc82b89a336c56495182a2939ffb0bd16ea6a8cd482c8370e02544f899c75381daad68758e2db75e6ad', b'1df40e469d07fdfe426677eb46a2acb72bd3ad25b6626546123b019b9c9ee593f01fdc7b7f1fae7456bd06c4ab85984a35c9668c4e6116a731a705c509f7c62e4d064a7d11b39ab7034785e291971423e8deb3f19c7c355af1ea24b14e65642feac8fd2a4ab4ac4c161752ee53', b'971e52ed98cb6af773e771d537f6d6009d084baaf94aede3b7882ad8faafb1596b18ff091e7e315cdd831450910dfadb8c6a1e73b7d87de02f7f84e09ae7481e894b6022f10588b3628e2c7761544a92359954c35d65ce0b9d81eb36fbab8291473d632898aa81584f124a2eaf84d0d0', b'8a97da3f1658dda4edc9bf7a8e552d48916fc94b2320ff6a3c287478a758af12df43ac59dc67ce5ce5094184c77a51d2be03712b19f06d88972625378049ef76639a93a0da16ebaa850fc82040a09d8b59ccd6e88bc429390e19d4385c8fec625626a2ce86de723ba2ed736b59', b'8a97da3f1d5bcfb7b69dbe43bf087f49a26f815a397ae252720e586bbd44b802cb5fb210df6bd341aa130ed3c97910c6a44a6a5427b07c9fa93c233d865afe4c2db1a3fdd142eaf29a03d96401ad86d359d1d0f9cec43e3f0a4d9d3f1487a9605638a8819c9b6b32aea46e615702995b7f0cd70ba31f', b'9286932c998a2b97f43ee7c72be4b1ebfe58614c098abada7b22f390a0a034b7075562467a3f6c59ae8845f6bf8411b6b193115e4a7249674786ac64352305982643d21fc82b89a336c56495182a2939ffb0bd16ea6a8cd482c8370e02544f899c75381daad68758e2db75e6ad', b'ae2c8437960b719779fdfed117f23ad70b4b9eba28432aca904a97677e932a9a7cc6580c3aacbce2e92031b51a033c5882db371e673aab5b5aefb201b0c3a3e02b13979383b409ed8a81601ca2518726d3940ed2b54b04287bc013980657d5bfd0c05f91d2d3f099f29a2c72', b'83c3e5779c6c5e1f6a18f1384c676ea98f3950aa4da8e3edea69df71dc061e0355683a3064774aeedbbdb001b28e309ef3768af4aa5fd5acd7125844315cfa6b5649660c54b4fc235123ad77e1032aaf9430e4f02670c0274dcae1649f3c35bbc37af2af5f367bd47ca432b6c9f7a538670bbaa3', b'6bb61da0fbdb1d066d75b11ee30b1a15d3fe16ae1440dcb4d4be624609eeb43c55b8e05ae0d0f0d764aa056165b5e5fa104c89654b6973c691d74e27a062c90406392f95de53d60590a85b377e7a2b2e28cf2915cc63578e906473388e304ea7eeffbc959a02d1ffc594095964c3ca4264', b'7efe0cf2e3d817523f7fbd1bae09155b84f61cae0b4bd6e4cfb32d5205b8b27449a4a45ceddbb9d731b44a7f6eb3aab30b05983c0a6f76dcdfcb4f2ca962c701147e3cc4d868f211c0ae61637372296922be673cff315e81d23c5c16c7214e90ffeef983c61ffab1e2aa4c5230d0944b3379', b'8ec4f5779262434b241ee830532863fb972b5aaa49a5e9bde96f9a77db500e4d54717664757d56bc93aca913f7887892a03587f8f84adaa0990d5e0a3010ef6448002e376ceeb9776636b377b3513789d45fddaf2963c92755eccb70c22719aa8b6ce9fb441d35f445b728aadee7a62975', b'73b71ee5b6dd1d523a7ebf07ae131115c9fe04eb444cc7e898ba2e5601e1a23c48a9b30eead0fccb68fa0b7a77a6bce0431b8270073d7dc39edb5c79af1df85c562a0bd1de69f302d2836a0c492c376929a03723ee705b9fcc', b'8c9ad27a1655cba2edd9be7d9c1c2052893b8e5a3f3df8637b617030b244ea4bd453ef47ce60d512ac0e0ec2cd7757cef55b46237af528a3bc3a2820c109c347428afffdc010a9ea8c0b95734eae8cd310d5dbfe8bd76c3d1557d92e0e84fc7c1339af9c9dd0797aaee2277e02059d1c', b'8a97da3f0b52dca3a2c3f66b80536e4e9c629a1f223db16e7d2f6937a710a8579b42a05eca2ed25aaa0842c081785fc1e555751529bf6c94970579638625e84168a7ffe0eb0cd6c5c618c17211b390da59d1d0f9cec43e3f0a4d9d3f1487a9605638a8819c9b6b32aea46e615702995b7f0cd70ba31f', b'ae2c84379202638422b9ffe325e67fcc744f9abe340479f4de71ba3175c72fcb7f9f171c77baaaf7bb307eb910037c58a1d22b1e643aa74458eeb204bcc6b2e02a0ada82cbb70cfecd8a3f039874937ed4eb18c3f04d5f324ac535a95219d5a585c906889dd4f799f4942d39cf6abe22a9', b'5fdfdca182d969511687f15d59323a489649d85b658e6e3d25b94808dda6d0a486dd8429a85ef4934b922873b0e827b92b74d10c80e5633043eff91c3e332a5b1a0d0555afaeac15562620067a0ce8afccdf0ab05819dab8e2d1abb288859e5172a4fa6f3135', b'05f50d03d001fdaa156a7ff900bcaae221cbec36a53b637e656643cfb782e8d6e649cc4d62399e2918bd1bd4ba9f914678dc658c4e7a07f865e600c148e3d07c400b407d15ba9ebe54578cd1b1c25c2497ddb2f8826f2460b1', b'bb64956581027bc32be0f4d452b422d94c40c2b319603e9ac461916a7ec16e885088256329bbadf1ab2368a95d017316f6da211e7b31ad1443e3fd10b090b4a836169e84c6bc45fe9894701d9372dc37cfa2099ab14b5a2804d934a25b19c9a493904e8d9cdef099fd873e7c8a66a02ffe8a', b'3110776252d0f8ea776e20c930a686bb4fc745fb0c3880c73d4b73d27c191aa5891fc7e12206e0f884f08b3f9635f39ab7b13686b4aefc4abd3068658e35ce4a60b8198e7d5d7bbe12133df63380b99e831c4c14e43b08fda203b9dc3de7ae4ec8c8dc884c', b'4a97c9e481df634c4299f65c59352c50871b8f5e6bca626e64fe4a08c0b591bb8cdd8629aa1bebd604c02862a7e831bf3d20d016cee52c3f41e9be13617b13604f5b0a3ab3999e535421201c5d36a9f2cbf2548f7e5794a2f596f5', b'8f88d6759b907887bb78fcce2deba1face7a23185db4a2c57f29b3c39ba1158d181b6f5b3f237904e98958b0ae8513b7fd815d4b4560176838b8eb75351414d027548205e42ca99225df7fc749392468ffbdba06bc7dc9c69a9f3f0451194d948d6d2453f0', b'9c8ad6731f17d7bfb8dff6739f526e598f7e88523869fe7f3c326835b65fa4579b43a343ca2ed65ba9110eccc8645595bc5c6c543aab7c9aa4332a29c212c37e39e4b8ccc00afce8c605ea6e6e9cdac90dca8efdd2cb6c280f50d12f5c96e1755a38a8c0', b'2c1e323b50caabfa382d38cc3cbdc8e257d34abe5c3c83c03057209573031ee2875f8fca1d57b8fefbf48c2d8174a0acaade0bccfaaee613a3227c2b8d7ad44729e14085675f63be131a28b13fd8b0b5f4511215cd2a40f9bc47abfa20889612d2c8cbd61222da6d7a911ce5c1541d4a1d', b'9286932c92893984af68e3f91babb0f7fe7b3d180fe6bded701f9fd091ba09d844426b143b3a7057fa8543fef98401ada9c746424d3b4e734788b02d2f2c40cc2d06dd13cf628ba82d9162c10a692a7db0e4bc00ea7f86ce988f7e094d19598f96696150bb9d', b'938cf83689681053611cf5335b232db4962f51aa4da8e3edfc6fdb62c1061f0540757667757d51eedcb2a317b2973195b7358cf2f853d3ad924642147b10fd604c1e75636bdf9a633f239a66fb552bc38920d58c1737dc634f83ec3d8e7332b68a7abbac5e2f32d573f72ebbdff7b035690bf1', b'9b8ce4258a61491f7614e4351e2a6cb5c02350aa56aee3edf262d563d7060805486d326278761fbcc6b2e60dfc8e37dbbb7c96a1b94cdfbad7115f013910fd604c1e75636bdf9a633f239a66fb552bc38920d58c1737dc634f83ec3d8e732eb79029f3a95926289b7bf623fec9baa6247157', b'8ec4f577996151587f4def0269733cafbf3e4bef4bf3f592eb45e523dc52195d51782b306c6d5abdc7b5a90ab2932b95a73592e9b71edbbad701580d3957bb784259623677a0a0323577ac66e0102e98955fd2b06863dd7e53d4bc309c7335aa8c79bba5526c', b'6bb117a0fbd5000b6d79b853fb175453c8fe08f5544dec938cea367e14f0b46e13bb9f40c7eaaacb30a85a6679bae5f21109cb7204693bc396ca4e27a062c01d157e30d7d36dec4281be6120776a2a787be7227af2225cda8e3d75289d771aa0fef4bc97900dd7ac83', b'4297d1e085c92c4e078fec5d1c3f6949940cdd137ec6626e7cbb4613c0e184b88889c83bb41bf7d61fdc2474e3a539bf2074d10c80ef6d3d48a8ac187d33385f12195e01ae9c924f0e2117176149fcf9def24adf6146d5abebd1b394a291dc5142a0b2672628dc797b4327c56d1b6365a98463', b'2c19383b50c4b6f73821318124a186a352d713f0432dccdc3544699c7d5514b7800fcbcc1053bcfffbe686398573f3a0f9890c95bba8eb5aab257422916ac8701bac519557457ffb07453a892aa787d9cd115151e22755bca21daecc20a0e94ec9ce9980073ad53e3c', b'0ca3e4a5419d9f83dc09fdd911efe9e14bf4aec50b9c46efed67a18f3485487f85d7434d4f52d03197d24f429dda2c87d2d801b02f80a149a3216cf306c0bb0a3a78e0d6c89ba28a2dd770a870f9d0ba24980196a6149182542393ce4c63d988bc7f152e9a46353e97dab88d4f6aae3c87fa1c6c0ec5', b'899a9f720e44daf0afccba7d865f2b1d9b7788583079f9524b75362c8c44a257c915bc6fc141fe01ab095c94d16f4d95a65c77073ead3f89a7273e729115f25a78b8bce7dd0df7ba821fc16801a086c90adbd7e2dec56c291b49d43f1d8ee0635e64', b'19ebf1e0438b829e9310b5c159eeace44ffffd88038c03aced29a28933d14f7881905e11466afc35cef94702c4cb01c0c9e21dcc03eca1728e2272fe09d0a916673ce1dddbdea3c236d075a934b7dea07d85078bad01c39941209d', b'0faea1e8448b99d0d106b1cf17e3acb249e2b396128105f9e37cbcc023ca406091dd48094e62e925d1cf645ed5dc31dad2e4069005c0ef5eb06175fe1a8cb01c7732afdec1dab69972ca439b64a6cb9170990a90f015bc996b0880d45074c988a070', b'52d8cca190cd62020c8be8560b7b2a548d1adc137ec6626e6abd4200dde185be9d94846ca511ecd618d33762e3bc38b46437d70ad2e36b3c0dfcb6483d7c3f525b191702af85db470b3318092201c5cb8bb110a07342d1bea39284a5bafade4b69a6ea722d668f49732c0c9e664f623db68f7b61', b'4297dfed92cb77120ab1c907482f16528a0cdd0079f169015aed4915c1f180a994dd802daa1bb99a15d33369a6ac70be3231ca5fd4ea697954edb81a2233385f1a1e5e12af949501083c1a013204f3f2dba00d8c2747d5a8f5c1aebbd985994d74a7fa663d76c6487c7f1093704f7730b88f30', b'8387826491977894a631ffc36ceceeeec47b3d1413b2eec57122b48bdfbc1e89505278536a206704e8804df7a2dd1a9c8ad3005e7d6f4f6515dcac1b2f043f8b2c52c346cb3b9bed72de2bc616243861b7adbb14ea6f86d582807e0a50505e92977e6f', b'9a9ad976155edab5a3c8a56fc85a225c9a60d957141ea53c681e7330b642f941e448806f9c60d540f50d57d981795695b5466b0421b739dca1216d269a1fbc5a79b4bee7dd0cfeba8519dc6e55e386c159d9d2e18bd72f22135ccb2e1187e7641d', b'8a97da3f1459c2a9edddb36e9b53201d84749c1f2a3bf42d7824742cba5eaf569b52a010cd6bc25da8180ecdd23644dda01369113cb73392e82b2227d21ef94a64b1a9b3c00db9fc9917d27b11abb6f04d89cad2dfde2938494ae22533bdba7e4738eb9e8bc63c38a4aa', b'3c13317253ccaceb762b24d271bdc0e250c741ee432a89903541208672105bb1864eddca1c5cb6acabeb8a349026efa3f99f05d9fabce21baa32252db50d941e38c714896d4324ed2a1806897786ac9893155a1cb23f4bf4a711aec023a2a75592', b'5cdfdcf59bc97e021b81eb130d3320488949d65c7f8e642f6bfe481393a79cb18e86d8248329adc704ed356fa6ba63a21b3af72093ec782b1df8a015716a23425b1e160ca99adb5808275f117307eeb09ff90b8a754f94bef986b3bfdb', b'918bd66181962cc3b639e7c722fce4a3c2603b0e0dbcadc77125b3c39ca1159b4156664023207b04e8804df7a2dd1a9c8ad3005e7d6f4f6515dcac1b2f043f8b2c52c346cb3b9bed61d87fdd592a327baca7bc1cbf6bc9c497983709435543889437', b'5cdfdcf59bc97e021b81eb130d3320488949d65c7f8e642f6bfe481393b89fa5c9898025b215b98f1fc76164a2a624fd642dd70ad2e72c2b44efb11c7f332a5b1a0d0555afaeac15562620067a0ce8afccdf0ab05819dab8e2d1abb288', b'3c13317253ccaceb762b24d271bdc0e250c741ee432a89903541208672105bb1864eddca1c5cb6acbde8823d9f36e89a8eca58c185aee61fbf7a661a8415ff1c22ec12d178486abe051920b830c8b78c83044f0db23f4bf4a711aec023a2a75592', b'9f81832c998421c3b63dabc225ece0f3d1603c1309b0aa927736e09a90bb5b8e55527a186a2d6050ae9543e5f98c00a6fd835e454f7e43200e89ff3d2e3e40dc2d48c556dd2e87aa6d8163ea2e7d6c6180b0bd16b82b9af898a7014e4c4d58cb89603c1daac19017', b'2c1e323b50caabfa38283bc036a996aa7fe507af580698d839403381451b349dc141dbcc4542a8f1fbe78c378969eee5ae9f1095aabfe10aa12c3522832cc50f39e8409560547eec550626a1219af883d0454118b22a40f5a01fb1cb29e7bd49d9c599820d35d36d7a911ce5c1541d4a1d', b'87ce9060958223d3bc07dc927debdef7c96a274e0e8aa0fd4163ae978dfe0b91491b6651383c7a4aae9b44fff98317b5b8951147437f422006cfb22d323f01d32706df13cd2794ed62c362d01d693c7ba6b0bd1aa47fc9c9939f70', b'8ec3ff77926c5e462412e17d582b6cbc9b7a4bd56ef4b7b9da7ed275c01518324f4e0923736c4dfec3a5bb44e789789aa170c5efb74a92a59e105e0a3010f4795f596a2166e1a0242e35a071f2452a95da08dee32976d73751daea2d9d3466b1967bbbae522329c834', b'e55c791df4c972cc62e974d015a9eeb4075eb7ec0cb52e8bc99bf7775319677023db9af3900101afbdb8db7a64802e80fdeb49901f54e1b9a6d96c17d0ef5d8aea9437ffa01f71153656819ba4c65a2510220e11540d44d49049a60ea97b3a5a731251f2ea580cc6b09ef271', b'f8147d50b6c26ecc62fc3dcd02e6feae445afbe204e16393c98cec60554c7d62249a92fc941554bf9cc7ed2375955192f9ef5cd85c63d0a1cddb763cd6b74881a4c75aa1cf39271a3057918abad4547536250f44441c07d4980deb15ec6c2b196e0855f8a44251', b'ae2c8437840b709036e7b7cb1abd6ecb4a4281fb2f432ac8d1508b6d6f933f9e2f8205527ff5aaebf4267db05d027d0cf6da3c4a712dba4144ffb217bdd5f7b03a088999cdf212e482da3907dd60df76c0b04ad28f6e036a50f128af504b92bebfde69b3c1d4f7cbac852221cf6fbf32e9c324bc9b06', b'4fd2dfe89dc578470c8bed4059342f06921cdd4365dd626e6cad0715dba4d0a39d9c9a38b510fed600dd2869b7e83fb76432d41ec7f93c3172dfed59254c385f1e184d16989fb47e543c0b002219e3e19fe10893274bd7a4f984adae98c0835133', b'9c8ad6731f17d7bfb8dff6739f526e598f7e88523869f7617d267c68bb6f9d068a529044c76bd301b62240ebfe255ec1b703690d33e4338ee821223f9715f24c2db0a0e0d142eef3991a956848b18c8700d7cbaddfd96c280f50d12f5c96e1755a38a8c0', b'8790ca3f1856c0f0a3c8a0799a1c2d4f92689a1f3f21f42d73226239bd10bf5ccf4fa310d661d412ad1c58c1816258d0e55076013ca53b99e82622729e15ef4c2da6a5f4dc16b9f59356c16844e38fcb18dfc5bdc3e91b7e4b4de23f1487fb234015b5a1ad88722eb3b4776b0a46855a7e19924c', b'3ea7e0e24ac885afe453ecda26f4a1f758beaeba0ca739bfe27dbdd030dc5333a8d95e180764f425d1ce7142d5c83b94cce6049a50dabb11f17070fd1a99aa4f727dfc98cfdeb48c6e827da027f6c6bd2486068eaf4681920a', b'9286932c9b8b349af428eed43ff0efa3d860205d1ca7ab927a35b39796a01e8c144f7914282a764be3890cf9aacd06abb8c7414f5068486e4796b031612f05db2b42d456cf2dc6af739f2bd315283a6eefac8a24fe299df882803b0f114a7595b6467253aac1d949f8cf', b'8c5b5ee5d5c760f173f239c431b9dc1a8a5c0ca0eb1ee2e1b1cf2680f384c6143519800a1775374fc7af5a79a25ff3d4ce32315dfec964c67b7488e0cae17a03b2753d2fe00496e352d36d692e580f962e9b55c51e70ce1394cfe22aa9a9929e0e3d7e3599b2ca', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712ef4eaa10c060cd4be50d4bd6d2795e95bc5c6c542fb639dcac373e269b14f94d2da1a3b3d607faf59813956952e39dcf1c98cee8d9c523245a40d23e5c86ec735a2ebece86d43c38a4aa', b'19ebf1e0438b829e9310b5c159eeace44ffffd88038c03aced29a28933d14f78819056185168f525d2d47953919f38d8c0e014cf18ec9809e06543fe1385ab5c6943e1f7f288bf9630926cb52db7dea07d85078bad01c39941209d', b'8ec4f5779262434b241ee830532863fb972b5aaa49a5e9bde96f9a77db500e4d54717664757d56bc93aca913f7887892a03587f8f84adaa0990d5e0a3010ef6448002e376ceeb9776636b377b3513789d45fddaf2963c92755eccb70c22719aa8b6ce9fb441d35f445b728aadee7a62975', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712e249ba10c26fd812a7180ec0c86551c5b55c701a3aa138dca1346d2b9d0fbc4f6cbca0bf9400eceed50fda7501a29bc259dcd1e2c6d3286a135f9d321397a9745c24afce86c96574', b'8790ca3f1d5bcfb7b69dbe43bf087f49a26f815a397ae252720e586bbd44b802cb5fb210cc6fcf12ab1858c1d33653c7aa406a543aac39dca73128339c5ae94779bca0b3cd0decba9d17c36501b781c259dbd1f8d9d72b2f5a4dd26b108dfa751339b2899acf3c35a7a4737a1246855a7e19924c', b'05f50d03d001fde416227fef4fbebbe220c2f925b7656c01533c169b8097f6dafa1d93326502b23a17ab0691bec68b0f63d4608e4e721db065e100d74ee19334773d076c03808fb81d05dece99cd6a0884c4afe6de3f3f78bfc71eeb4e7638', b'2c1e323b4cd0bdfd6c2738cf71bbd5ac549244f6437985c37c556f9b74125bb69d0fc9d21455aabcb3dbb46ed572dfb1b19b1b86a985e035927a7b31986ad05631b80c847c117afb4e5620a237c8af82cc454a12b23947f5a013f8d121e7ba55d3cc998b0775', b'4297d8ecd3c26356428fbe430b342d53811d8f5c6c8e6a3725bd4e13d0b49da39d9c862fb90db7d63992206ae3a970a1363bdc0ac3f62c364ba8b411717520561c114e0d98a6cf10130d0b1a771ba9efe0ee2ba03444c0bea091a2b6d5c1884674a7b36d3a6881', b'bcc0f130843d58605349b629613365be927950d5578fd9feeb7ec820c25f164d6564307973714babddb9b517b2953edba36097f1b74dd7e99e1517103f55bb7f59187c276aeeaa777e38ac7ce7103696da1ed7af6865d17f54d6ea219e3628aacd', b'9b8ce4258a61491f7614e4351e2161ba873113e26697b2fcf155ce78d754581e7e6f194f2e764bbc83acbf19b2973995f37c96a1b750d7e9800e58173210f86444156a2166eeed257b39e57bfd4436d09216c8e32976df641dc4f4219d732eb79029f3a95926289b7bf623fec9baa6247157', b'938cf43e9b63441f621cee311e3365bec03e46f94deea684a560cf63c6060d02546f32307b745ea9c8ecae3bc5ce698f8c618de4aa0dc196992968573944e93c5d00737332b0fd777936bc61b34436d09e109baa3c24c56552ddfb6a', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712fa06bf55dd7dce5ce50a46cb817855c3a04139192fa039dca972203b810efd4268f5a2f6c207ebba8104dc6545e388c900ccd6e4c5d16c241f4e93', b'a3175eef8e9967da04a728c01ca2d00a9b1b5f90e371dbbebedc2f80eba2ec005005ba5e107e2905948051448e03f380c56d3404e29b6c9f3f7292e6c0fa7214e6603c6ce712dbac76962c6d7d195b8e39d441d50f778112d296e026a9a9929e0e2a727a83aec41a455a', b'91135aa885cc7df63cfd39c32bb9981c88515fefeb52e5eaab9835efccefa0545b19b71b0d233623dabf6b059318ef90cc7b3c04ea9d29dc3a798ffdddb47515e6703c22e057cbab748660602e5740927c9d5fc418769c09829baf27e1a8d78d023c643599e193104f540331fa83d4976161f228caea', b'f8147d50b6c26ecc62fc3dcd02e6feae445afbe204e16393c98cec60554c7d62249a92fc941554bf9cc7ed2375955184e7e15fd60f7faf999fca640fc3b856c3ffeb52fbb1124b002c40d3c9b0f61a4a1b790545555857c2830deb15ec6c2b196e0855f8a44251', b'a082976b8fd530bc836cbad213ebe9e6d33c2622139a91817024b2d38fb706c8785270516a26664afacc4df2b69806e3ba82455e4b7540200681bb64292a16d12c419d56d23695ed77d364c00d693a7ca9adbb14ea7987c3d68a3b144c5e04', b'2c1e323b4cd0bdfd6c2738cf71bbd5ac549244f6437985c37c556f9b74125bb69d0fc9d21455aabcb3dbb46ed572dfb1b19b1b86a985e035927a7b31986ad05631b80c847c117afb4e5620a237c8af82cc454a12b23947f5a013f8d121e7ba55d3cc998b0775', b'7efe08e5e4c7011c6d61b61cae0a1143c1ed4fe30541d6e4d9fb2f4813ecb07745e8ae4bfed0eb8530a8037364e7a3ff020b902c03424c9bcec8783daf27dd5b14013aeae93fef45d3ec743a6b3f387322e42f33fd37199487232d', b'6ddbd8e6889c647d35daaf47262f2143905adc6c64e1587d6baa5551c3b88df0a8dd9829ae0df69850c52968e3a635a721269812c1e669794ca8b40122672d5c1e4a1000b1948901132016177649fbf2c6f40c96694d94a2f596f5', b'315636761dcbb7fa382f77d123bdc2b743c613f14a7981c97c516980790016b1864ec1dd1041ffac92a48237c467a0b5ab910dc0b9aeae1ca128723eda32ff7878a914be7c5972ec460516b80bb7eb84d7171311eb2308f3a854b5dc6ea3ac42d5cfd0890c2889', b'4ec1dcf38ad8644b0c89be4a162e3f43c20cd956788e702f6baa420593a883f08693c838b41bb99904da2475e3bb39b52174de13c1e5776945d78e5c60671343130f0c56b4ae956e386111066059eae5c2a00b99274cd1ade2cf', b'31563f7a4bc0f8e27d2f25cf34b686a44cd354e51c31b3e7680374ad6e1d1eb0c15cf0d03a6de2e2aff6d32a9d7ba0aaaf9b1b95aeb2eb5ab42c7437997ad4472dec4096605479be1a182ca56485b184c7454a12b23349f8ab54add562e7bd49d5cf99820b36ce237b8302e59215155652a5ad', b'2f13777d51c4bff5282608f665e3d29d54da56ec1f2ab3de136d339c6e074bb28b528fd30041a5acb9e58f3b8a65e5e5ba9107c6aab3ed0fa23c66658935ce5c39f51095615e79be021f3dbe648bb784d0064a0ee72d08ffaf04b1d12faba052d192', b'e55b731dfbcd6fc162f27b9d05fababa554bfbeb0ea06991d987da450208644e249399edc21525f19ab8bf2021864184ecf31bcd037faf9a909c6b0dc5ff4286e59461bde50779076447c499a2dc0760643d0e11461a429b9244f005a26f6e1572091cf1af500d95f0', b'811e59e19bc07be03df66ac763b9de4f995d5ebfe24de1adb6c43cd7e0ebf97f5359ee0a20642d19c6c347699323c293d2763314f390749f3264c1e6c1f13703b2752138ec19dfe36b9c656a7a1940807c955ddc5d658d149b8af936e4a8998949', b'8ec4f5779262434b2419ee3b582e6eae8c3e03fe51a9e8aaa563c930c64e0e4d456435796e7150a093a8a944f3992cd7f3618de4f858dea8901d070c0867af3d59267a3b66f2fe2451398a4da05e2d82ca0fc2be6876d7644993f537d33e23ac8665e2e8432735da79ed32a782', b'8c5b57e983cc2fe936f26bda26b2980985494bb4bd56dbdae49929efefb3f452371e8010304f7612c08204468411bdcfca673304f7816c9f227280e0dab46318a760733bed12d6e3749d69772e54468838d458c35d698f1897cffa23a5ed83950e3d373e9eac8d1649070227a9c7dd9b6e74fc', b'bcc0f130843d58605349b629613365be927950d5578fd9feeb7ec820c25f164d6821327979764beed5bdaf08b28e309ef36180f2ac109280d70c42172310fd6358176a7332b0fd777936bc61b34436d09e109baa3c24c56552ddfb6a', b'8fce9265908b2cc3b239e2ca6cebe9e6817b300e09fbeefb3e3ab5908bee1d87415572147b7f2504e8804df7a2dd1a9c8ad3005e7d6f4f6515dcac1b2f043f8b2c52c346cb3b9bed61d072c6593d3235bbabf51abe389ed599863953', b'2f1e326f55c0aaae6121228125bacfac4b924af159798fd132126f803a0c14b7d25bc7d71b59f1f5b4f1c3398568f4e9f99805d4bda1be12921e21749e05d44729ea5392575f58c146183da47498a197831c4c14e03b08eea713b0d160', b'8a97da3f0b52dca3a2c3f66b80536e4e9c629a1f223db16e7d2f6937a710a8579b42a05eca2ed25aaa0842c081785fc1e55a77002bb62e89b8266d269a1fbc5968a7bffcda42eef29a56dc7301a786ce17df9ee4df986c2c1658da304c8ad647077bafb186d37928f2f7587c3839c55c6519c712ae4c', b'11ebe5ec559699d0d506b4c259f4a1f70af9b89616c646c5ac6fa38127de1e7bbbe70c4c5352f36dc3d42345aad111eb92e91b8d40c3b640f17b69f90fc0bf006f72eb989c8be1c235c365bf70e3d0ee609e4f8bb74694854b39d494', b'b62d8772d407718d2da9f6de1da73a984c5e86af2f596d8bd150812273d22b926181461c73a1aaa3fa317ea1094c7414b7d4290e7c009f0005ffcd17bdd5a5f32c2594b9fce10bf89fca200d8026d47ed1a214ddf058593f04cc39ae5b5e8f', b'938cf43e9b63441f621cee311e3365bec03e46f94deea684a560cf63c6060d02546f32302c280feec4bdbf17b29c349ab46ed5e9876986f88339430c3242a87f7217410c30eeb9253e27bc6fb34436d09e109baa3c24c56552ddfb6a', b'9b89da6d0243c6b9a3caf66587493858dd7e9f5a3969e66c7235623cf359b912d448ef56c36fc649f51571f3952744eab15b7c067db70392870d7e3c8608ac5974a8ece7dc07b9f5811ed07201b080c31c98d1eb8bd0292b0817', b'ae2b8e37990f6c9a79e6f19c07a16ed9595ed2b529432ac7d9488c6c7c933b976e81110c728a8eb7aa274ea01509604ba5ec3c714b6ca64046bbe21aa890b8b52d5a9e84c6b308ffcd9835179c73c07287bc1f9ab14b527b48c72aae5b5e81a295c2068a97dbf1cab2', b'341f317e1dccabe06c6e36c33ea7d2e247d747ea45378b903d5c64d272140dab9c48839e1c46a2acbae68c2f9026e7acaf9707d2fabbe01eed2f79248d21904713cf54d07c6e63f610047aa51b8697b5900b5713a22e51e1ee16bdcc20a0e7', b'921e1fe580da7ba531f275d52db5dd4f8f444da8f60eecd2879c6cc4c4aff945765eac21115f1a4fda8446068d15e080df6d2f57f3806aca346292b2cafb7903b3792338ec18d6e36c9a786c2e5a40882f9758df0877ce1f939fe627e8a19e8e0a60', b'11ebe0f1458a8492c613b88e14f9e9e15feebe80119b46f8e329bb8829d61433ad905e11466afc35cef94702c4cb01c0c9e21dcc03eca1728e2272fe09d0a916673ce1dddbdea3c225c36aa970f8cdee709e0089e3078d8e0432cbd951759cd6', b'0ca4eea55c9983899308bb8e0cf3e9f446ecba9e528039dbb838bbbf34cd4b61d7c367136852b46bd2d420468cc27ed5d3e24f911fc7ef51b86775e41cc0b61a683cebcac8dabc9162c079af31e2ccab24860ac2a21486d7483ec5d34a61d997ac7f462791073025d6', b'52d8cca19ecd75020482ff54026b2179b55d9e4755da6f2b77ed543edd8eafe387899a7cac07e4d612d76163aabb31a1343bd111d4e7687944eef9113e666c511a031249e7938e55472b10073208e8f99fe40b906a4fd0ecf987fbb29ad0cd4172baae222069d608', b'ae2c84379901719779eaf8d11fbd20985c5a8bfb365265dbdc5bc56572c538db7a964a4872b0b0f1bb357db51a17221089e4660f6000bc5c51f9a1108ade989f6c148e8493a21cf1cd8a3f039874937ed4eb18c3f04d5f324ac535a95219d5a585c906889dd4f799f4942d39cf6abe22a9', b'8790ca3f1856c0f0a3c8a0799a1c2d4f92689a1f3f21f42d73226239bd10bf5ccf4fa310d661d412ad1c58c1816258d0e55076013ca53b99e82622729e15ef4c2da6a5f4dc16b9f59356d36c40a4929711e7e9b99ac2133e125ccf780fbde75f6c79b59a808b6c23bca4737a1246855a7e19924c', b'8387826491977894a631ffc36ceceeeec47b3d1413b2eec57122b48bdfbc1e89505278536a206704ea830ce3b68017b7b58e5f4d026c48721387ff33332214d12c419f56dd2e87aa6d8163ea2e7d6c6180b0bd16b82b9af898a7014e4c4d58cb89603c', b'341f317e1dccabe06c6e36c33ea7d2e247d747ea45378b903d5c64d272140dab9c48839e1c46a2acbae68c2f9026e7acaf9707d2fabbe01eed2b702c843d8e0f2af4018673017fc1224278a21b9cb08fd156503efc1177afa000aa953ebeb4', b'3956277e4fd6b7e038393fce71bcc3b445c013f34d3d89903d126d9b69011aa9970fc1db0357a3acaff68a3f8026e6a9b8991285b285d94efc3d4a31823fd21c3fc70eae570279ea074639af39c8b984da114b08fc3908f2ab03f6', b'8fce9e6d8280788fb139f9c829fba1ecd76a275d09bdab926735a1918cee0f80554f3643222a7b04e18249e3f9801badb9c75859027d4b610094ef2c1e1c54893679c51ede30d5be49df44ea4a272967efb4ac0eea7588c393c82b0d0e195e93906a6159b7de8057e8c169faf0420c6f2be928', b'f45d6855f3de21cf30f469d850faf5b6425ab3e40ca62e9d869df17a164b7570349292f8d10908bfb188ac3d3a991480fde755c44c7ce0848d822205cebe4a88a7dc5a98b457602b304dc488f0da2b6b0b15585f531a17cb8750a61bbe613a13691c12', b'ae2c8437960b719779fdfed117f23ad70b4b9eba28432aca904a97677e932a9a7cc6580c3aacbce2e92031b51a033c5882db371e673aab5b5aefb201b0c3a3e039169b91d8e20dd3bace6100a272db72d5f809e5be7668684ada2ef74540dced94d94b89d2d3f099f29a2c72', b'd7587d5aed9c69e715a92cc92ffdf2be551da8d20c8e51d9879bf72246406d31199ddce69e135afbbac7fb263480518dfafb4dc64c6ae38198937143c6b04396bb947ca0f50a78542340d5dab4c1157164330444510d07da925ae715bf282915730f59f9e4', b'49c2d0ed978c754d179cbe5c0e356942900cce5e798e683c25ad480cd6ae9eb5c99b842dbb05a99e2fe57536b79724b921268b0cffec43061ee6ad1a6163354a5b0f1216a2d18c480b3e5f1a7b1bffbcc6ef11df734594aee588b7afd5d1854074a6a92c', b'7efe0cf2e3d817522b7abf14f5541c6af3ab5efa3b51dba1cae8317e0ed78e2f4ebcb21ef8cce48536b3097e20aaa4fd4305983c04737e8f88d4483aa262cc000e3230d7d362a143d4b2242a786b363d33f9347af2225489c2236b249d3052a6f8a6f4909b08d6ffcc871a1c21cfd44f332a', b'ad21c17a811d76c33be8fbdd1cb12b9848549ca8365e69dedf4b962278dc33887a8b1a4873bab7a3ec3a65bc5d0f7d16a5d03b51612ce85755fbfb17b4dcbeb33254da90cfb302f7dd920f23c937c748d3a31fc8e34a68356bf16fa9414b91bd99cd', b'bb64956581027bc32be0f4d452bf2fd60b5281fb29596f8bc7568a717e933e93668a0e4e7fbbf9f1ee3d31bd13187d58beda211e752da54714fcfa06bb90bfa92c5a9297cdb616ac8b9631138636db48f0ff4bce8f4d5f3e569d2f985b76fefe8ec454dc82c3fe99fd873e7c8a66a02ffe8a', b'47dedfe4d3c57f021586ff47592c2c068f08c4562ac7736225bf4b16d2b883f0819c9b6cba12f8910b82295894fc61a51b20d01ad2b17f0643c7865b3f673e070b130345a5949e4f4b721e1e6508e3ef9ff70d936b0ad6a9be', b'938cf43e9b63441f621cee311e3365bec03e46f94deea684a560cf63c6060d02546f32302c280feec4bdbf17b28e37dbb77ac5e8ac1ec5bb9808504a7756f76d4a023e3b5cd7f9667a08b17af6426a83a511f49c7b6ac6650dc3e539', b'91135aa885cc7df63cfd39c32bb9981c88515fefe44aa4eeb1c633dfeffbf3452409b0101a302310d5974f069533ca948d761e50eb8c7b8c28488fddf6a77904b4242335f857cbab748660602e5740927c9d5fc418769c09829baf27e1a8d78d023c643599e193104f540331fa83d4976161f228caea', b'11ebe0f1458a8492c613b88e14f9e9e15feebe80119b46f8e329bb8829d61433ad9056185168f525c1c76653d5d02c94d5e8009450d2a144f17464e90e93bc413a7ae3d9cac0e18a1df528fd24c8cba661835c919c08aca81739c7c814768085', b'5fdfdca19cc2605b429efb410a3427069b06da136bdc626e61bb5415daaf95b4c989876cbe1bfa991dd7616eb0e824b92174c81ad2f163370df1b61d717520561c114e0d98a6cf10130d0b1a771ba9efe0ee2ba03444c0bea091a2b6d5c1884674b0bf2220748f447022', b'2f1e326f55c0aaae6121228125bacfac4b924af159798fd132126f803a0c14b7d25bc7d71b59f1eab7e58421d46edf92edcf1deaaeb2eb08fe3a4a2ba505934138ea5091714c37e71a0369b52586acc6831c4c14e03b08eea713b0d160', b'341f317e1dccabae6f2636d571a5c3e24dd358fb0c30989c7c546c937d0e4baaad789b8f016da5e4bef6d029bb68cf9aea901dc7eaaaf707ed2879328b23d30f24f913c16a5472f0595628ba3389a19983124a0dfe7e4af9e0', b'8a97da3f1952dda4edd9bf718d1c3a52dd6b855e253db16c3c35753db610bd53c806a95cce69da02ad22799090626fc1ad566b473d9b32b397612326804aec5070f5fea3941bfcfb8705956146acc7872dd0dbadd8d32f25145d9d291991fd304723b68bd2d26f7aafeb703c', b'9a9ad976155edab5a3c8a56fc85a225c9a60d957141ea53c681e7330b642f941e448806f9c60d540f50d57d981795695b5466b0421b739dca1216d269a1fbc5a79b4bee7dd0cfeba8519dc6e55e386c159d9d2e18bd72f22135ccb2e1187e7641d', b'1abee8e955d8949fc615fdc10eeee9f658e8bc8811c809feac7aa08d25ca4076c4d6541c4076b76df9f1240781e02adcc4f55c8c2fdd8062e27f68f84b90a0123a79e3cbc89ba68b2ece3ca439e5daee7d9e1ac2b709c395513edfde0472919db07f156f', b'8a879069d4833482b323bbce13c8b5b2d550211518a7fdc1413e8fbccca00f9a044b6f496a266604f9844de4f99a17e3b0865a4f0272532c478eb333203213982a47c256d92783a33a916ad90e282466ffb3bc1fa6388bc2d8', b'3956236948c9a1ae6a2734c971b4caa347c903f6730ed881286d749a7f0748b1ad41e0e1465ca5feebf49a27c46be1abf9971a95b5b4eb5aba217a368f7ac34725f404936d5f37ec001869bf2a9cb7cacb0c5041f32c45efee03b0c020e7a148cf9cd1870c3fd46d73820fa0845803474af9', b'8997da6b1352dcf0abc1b77b930c2662aa2fd84b143df9686e727407bd7f9501d552bd00df77dc12bc125b84d57e59dbae13601b3be43f9da6722220d203f35c2da1a4fada09b9e39a03956340ad9d8b59c1d1f8d9d36c38135ed53f52', b'8387826491977894a631ffc36ceceeeec47b3d1413b2eed47231a798cfa624bf000a626b3e277056bd9f73fe96b241ada995015a5b660777089dab2c613905d9264fdf119b2d94ed72de2bc616243861b7adbb14ea6f86d582807e0a50505e92977e6f', b'11ebe0f1458a8492c613b88e14f9e9e15feebe80119b46f8e329bb8829d61433ad9056185168f525c1c76653d5d932d5c6fc5f972fe4fb0ca54e68e21e92ea1c4572c0e79ed5a59072d265b170f8cdee709e0089e3078d8e0432cbd951759cd6', b'bf3284658d1a6a8a37eeb7c51da738dd0b5e84be34176cc7d1599e3273ec0acf3e92354872b0abb0e80c7f9b225f7c0ca4832247697fbf555afff707f5d9a4e03014da82cbb745e399923506dd75da73c2eb15dcf05f523a5680', b'f3417551f28c78d737ef3dd207e7babf554bbae011e16198c99cea7f53567e74709e90ec94460df6b98bac263c8614d4f3e25ac4173be7a9aede3317fdab4596e5877690ee294b472a51d3cab3d009253d251e11530707d98b44ea08ec7c261f6e094fb9', b'1da2f5ed548acd87c10ea9cb59f3a6ff4ff9b58c0c8f46fbe37bbb8860d74b7280d9561a0762f525c2c930459ad23bc0c9ee019850d5a35cb66a2ce224b7ed5e6e43fbd0c8c9e2911dcc539363f9cbbc3481169fe3118c85503f93cd566f8d91b76a48', b'8790ca3f1656d7f0afc8f678814f2f4d8d7480513f2cf52d75272721bc45ea54da4fa31c8f6cd446e50441d1817742d0e557761b23a138dca1346d2b9d0fbc4d62bbb8b3d20ef8fd8e46dd5f76f7d8d326ccd6e8d9853f151476e2781296fb204333a6ce86c96574', b'3110776252d0f8ea776e31cd30b5ddf248ed64aa1d2db3c4345772c1692a158dad1cc1ca0702a1f5a6a494328572a0bcb68b1fd0fabbe20dac3066658e35ce4a60b8198e7d5d7bbe12133df63380b99e831c4c14e43b08fda203b9dc3de7ae4ec8c8dc884c', b'1abee8e955d8949fc615fdc10eeee9f658e8bc8811c809feac7aa08d25ca4076c4d6541c4076b76df9f1240781e02adcc4f55c8c2fdd8062e27f68f84b90a0123a79e3cbc89ba68b2ece3ca439e5daee7d9e1ac2b709c395513edfde0472919db07f156f', b'96c5f632df644351705de63f513279fb872f57fe50aee1ede464de30da471d044f667a30746c4ceed5b0a703e9ca30a48421d4f5874adaac8555443b397fc43f430d7c6373f9b0776f35aa67e7103e998c16d5a46865dc731dd1f92d9d3468', b'6dbb15e5fbd60b006d62b612fa441a5ad0bf08eb1051daaadffb354901ecf1654fbde059e9dbed852da94a656faaa0e70a018e6f4b7c3bd890d2432cb524da04472d20d7d967e411ceba24257a7e3e666bf8180da7614da5963c6633c06365a1c4d9af9f811e95afd4885f5031c1cf15', b'6dbb15e5fbd60b006d62b612fa441a5ad0bf08eb1051daaadffb354901ecf1654fbde059e9dbed852da94a656faaa0e70a018e6f4b7b77ce98c7172198159b59130120cdd37eb242feb24b1c25712d6f6be03e27b331198d8d3a672481764fa3abf5e8839a07c0ffc2935f5031c1cf15', b'11ebe5ec559699d0d506b4c259f4a1f70aebb184059356e4d35efbd134fa5a7b81c20b0e7863c85a95c86444c5cf27c981f30a8c049def74f17b69f90fc0bf006f72eb989c8be1c235c365bf70e3d0ee609e4f8bb74694854b39d494', b'5fdfdca191c97f564288f2521e20794ebd3e9b027ef1732660ac1412ecafbf8fda939c3eec0ee08b50c6286aa6e824be6424d41ecef62c380dfcab0d34333b56084a4c55e7889e4015215f137506b4bcebe801df744fd7a3fe85fba990d6990569bdb7677472dc067b630fd8', b'9fdaf525867958566a1aa72451327bbec02f55ef4be0f1aceb7edf74924f184d4e6f7664757d1fa1c7b4a316b289319fb6358ae7f858d7a8854817023b51fc771d11510437b1b9087a3fa060a043069eb52088ad3c76826744ce', b'8c9ad27a1655cba2edd9be7d9c1c2052893b8e5a3f3df8637b617030b244ea4bd453ef47ce60d512ac0e0ec2cd7757cef55b46237af528a3bc3a2820c109c347428afffdc010a9ea8c0b95734eae8cd310d5dbfe8bd76c3d1557d92e0e84fc7c1339af9c9dd0797aaee2277e02059d1c', b'7dab11ecf294081e2c71a543e63b230195eb30fa0c40c1f7cb842c6e3fabbf6852f8b057f595e0ca31a84a7977a9e5f711098a71183d74dddfcf4824a22dc10d473b38d6d32cf658cdb0242b7f6d3c3d22ff327ae73f1998973d6f25d36452aae2f4efdf', b'47dedfe4d3c57f4c16ceff51162e3d06850cdb4763c0606e64b04341dba086b9879ac46cb50aead611d02e72b7e837b8323dd61880e460384af3e9000e4478060f350a0da283c852383c302d2107eeee8ff01d82274bdaa8b083bea29bc2c3', b'8a97da3f1658dda4edc9bf7a8e552d48916fc94b2320ff6a3c287478b55cab55c016a76ff83a90469a0946c1d32543eaab7c464720b02eccb82b30728612f90969b0affac70bf6f4d502da2040a09d8b59ccd6e88bc429390e19d4385c8fec625626a2ce86de723ba2ed736b59', b'f0147a51f7cb7a882ac24a8941fdc5af4f4ba9be119e60a5b6dceb66440960682ddb8cfa831515f1f590e421759a1482f0fc1bce0d6fead698ca6f0ad1ab4c98f2946baaf60366543057c89fa789156b3d3e0358490f07d59b5aa8', b'9fdaf525867958566a1aa72451327bbec02f55ef4be0f1aceb7edf74924f184d4e6f7664757d1fa1c7b4a316b289319fb6358ae7f858d7a8854817023b51fc771d11510437b1b9087a3fa060a043069eb52088ad3c76826744ce', b'00fa4b1f9f1daeec0e6379f610a390957396f90eaa636e5301212dd5a7a9b3dde0088f62750be17e19e91e8cab92cc1f7ac8788c4e721fa324fe1f964df5cd39044a4a3202b397f01f12999db1cb442397d3b4e1982a6664f3d21afb53317170eec5e56410', b'1e1a367c4695b0d14f7a66d50ea6cea7528140c14216b383324672c26a0c06e2a647ca9e0447b4ffafed8c34c46ff3abadde1eddb5fae709ed2e7a2c843d805b23b80c847c117afb4e5620a237c8af82cc454a12b23947f5a013f8d121e7ba55d3cc998b0775', b'8fce977880973181a12cee862af3e0e4da3f3d222ae1ffc64124a8868dfd08b75a744907243b6714fe9551b0b49452b0a884524f5168077408cfab2c28385a980b06df13cd2794ed71d07dd059262f35ababba18ea7987ded68d261e574a4fd5', b'2f13777d51c4bff5282608f665e3d29d54da56ec1f2ab3de136d339c6e074bb28b528fd30041a5acb9e58f3b8a65e5e5ba9107c6aab3ed0fa23c66658935ce5c39f51095615e79be021f3dbe648bb784d0064a0ee72d08ffaf04b1d12faba052d192', b'9286932c92893984af68e3f91babb0f7fe7b3d180fe6bded701f9fd091ba09d844426b14282a6650ae9845fdbccd06acfd975d4b4c6f0761479bad21246b17d9310683469b3b83ac64c22bd41e2673358bacb053b97d8ac8988c7e1f474a5edb8d702c58feda9a19efdd76b1', b'2c1e323b4dc0aafd772077d639bd86b141cb40be452dccd33d5c6e9d6e5519a7d24bc0d01012a2e4b4f18f3ec468efb1f99707c1bfa8fc0fbd3d3531823f805f29ea138e661160f61a5620a5648eb48bc41e1309cd091cadba2baccd2bb5fa52e3d2f6b95135d33f228013fdc1511c5a5db0a3e6186a', b'3110777d51c4bff5282608f665e3d29d54da56ec1f2ab3de136d339c6e074bb28b528fc71a47f1e8b4a494328572a0bcb68b1fd0fabbe20dac3066658e35ce4a60b8198e7d5d7bbe12133df63380b99e831c4c14e43b08fda203b9dc3de7ae4ec8c8dc884c', b'47dedfe4d3c57f021586ff47593d254785129f5b55f9337f71815309d6b3c3a3b693a713ef10ed8440c2387ae3bf35f12935d31a80eb78750de9b51f306a3f17130b0d45a5949e4f4b721e1e6508e3ef9ff70d936b0ad6a9be', b'e55c791de6c973cb2df33ddb1ce8fda0174684da56f07ab59d87e060054a4f7f1fa4cff185144aefac9aac393d9b5187f4f74883057faf9598846c0cd6ff4f96b7d06aa1e546671c2b50cd9ee3c71b7164230545421a55ce8e59a618a46d6e0a62094ff8a411088eb1d1ec2c1b234eb08b2b26a94e74', b'bb64956581027bc32be0f4d452bf2fd60b5281fb29596f8bd6528465608335a458d25b4845a1b1e6e960628b13234d4bb8c7200e6426b51443e3fd10b090b4a836169e84c6bc45fe9894701d9372dc37cfa2099ab14b5a2804d934a25b19c9a493904e8d9cdef099fd873e7c8a66a02ffe8a', b'9ec9f63e9164445a6a18f42e1e286bfb903f51fa56b3e3edec799a64da434b1e55602464747658eec3b3af0ae6da379df37489edf85fd1a19e0341013a55f5780359683f62e7b66766089226a2440684921ac9f03b5bdc586280f230816336a79e', b'811e59e19bc07be03df66ac763b9de4f8f444da8f60eecd2879c6cc4c4aff945765eac21115f1a4fda8446068d15e080cc773354ec9a6c9f3264c1e6c1f13703b2752138ec19dfe36b9c656a7a1940807c955ddc5d658d149b8af936e4a8998949', b'59b219e7ed84062d1a22ef07d1101c50d6ac1cd10a6aecf7d6af301110e1ac3c65a1b446edc7b9d236b31e7320b4aafe06188375057a3bd890ce5321e730ca0903373ac29663f311c5b3243079723c6933f9293db3275688963c233681794ea6e5e1b2', b'97dfdb761f59daf0abccbf70c8482658dd6f8c4c3f67b1443c2b722ba710ac5dce48ab109e3e9112b21c57d781625f95a15c391222a53b87f83a1205c64be87679bda9e18711c6f4ba29866e55b1d9d700c59ee4df963b381557da65', b'921e1fe580da7ba531f275d52db5dd4f8a4742bcfd57e7f8bfdd2e90f8b4ff537100af0a167f2b5cd29c5551865cf5ffeb367050dc9d61da292492cdc7db4843a860217cf50ec5e36c9a786c2e5a40882f9758df0877ce1f939fe627e8a19e8e0a60', b'0aaeece05c9a88829313b5cf0da0a7fd5eadbb89038f1dbce45698d471d171678cd54a4e5452e94af9957e42878f2ecddca7089a04c7a653b6316be21a94f9167569afcfccd5a5c22bd13cbf3ffadaba6d9c0a91e307c3804b39d7df56608c94f97e12339b0d2776979cf1921a6daa7b', b'8dc4f5239768421f7d12f27d4a2f64b58b6a5ae54ce0e5aceb2ad562925f041801753e7973731fa8dfbda11fa29207ace72491deac56d7bbc415680a186fa862590b3e237afded2e6122e571f25e2ddcda06d4b63a61926554d4f430dd', b'9b96cb771e458eb6a1ccb167d854116ac92a9d603f21f47f2f3258369c6ff95ccf54ff40d6738145b7145ac181655fd8a047711d20a37c8ba720393ad208f94869bca2f4940debba911995734eae8cd311d1d0ea8bc123380e519d3c0e8bfd795d2df5', b'a082976b8fd530bc836cbad213ebe9e6d33c2622139a91817024b2d38fb706c8764e7f582e6f6c4bfb9e0cffae8352a7af825047513b4872479cb02924240edd6243dd05de6291a47add2bdd103b3835a6aba053be77c9c583813219024d429e906b3213', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712f206ae44db7cc850b0094b84cc6f10c6b0507a113db77c88a772393a9b09a60944f5a2f6c207ebba9217c36501ac9b870dd7d1e68bd722335a5cc5280991ec3e', b'341f317e1dccabae7e2236c62ae2ce9d778602ea732d84d52e0173ad743a24f19c5bdd8e054bacacacec822ec471e5e5b49f02d0fab3fa56ed2879328b23d30f24f913c16a5472f0595628ba3389a19983124a0dfe7e4af9e0', b'1abee8e955d8949fc615fdc10eeee9f658e8bc8811c809feac7aa08d25ca4076c4d5540e422de169c7c16b069de0098090f3308b18d6bd0ea24e72c524d3b71b682cffc1d09ba68b2ece3ca439e5daee7d9e1ac2b709c395513edfde0472919db07f156f', b'2c1e323b5bc9b9e9637e3ffe06e697b67fc65bfb5e6a9fef327d5fc1740109f28256d29e0557a3ffb4eac32d8c69a0b6b8871a95b3aeae19ac277b2a9e7ac24a6cfc0f8f6d1164f61a0325b26486b79e830c4d15f72c5ae9be00f8d126a2e951d9ceca890c7bd0257dd003f3c1511c5a5db0a3e6186a', b'800d5afa8cdd67ec3df439cd2ca3ce0ac94d5aaaff1ef3ecbedc38d4bbbdfd416316ef162047714dc0af405e981eaed3e36c0e7bb0877dcd6b6798ef89fd6450a97a7338ed1298ac6f9b69762e4a468239d45ed65d628b1d80c1', b'19ebf5f7449494d0c10ebec659eda8fc0ae4aec50d8603acfb61a0932585487f85d7434d4f52d03197d24f429dda2c87d2d801b02f80a149a3216cf306c0ba077370ebcac8d5f19037cc3ca53ee3d0ee6c981cc2a2148e840420dbdf4a269191aa2d0e209a0231769988b4de0a63b12190b3', b'91135aa898c67cf173f770d225bfdb1a855c0ca9e15fe3f6e0c002e7afeae57f7005ba0c4c631a12fbaf0758891eadd0c57f6150eb8067d87b7e92b2ddfc7250a2713025f61ed7ad3b8763246f5a5bca7c8059d55d768b0f86cfe620a9a0928f02226e7a83a48a19431d1e3bf4', b'9286932c998a2b97f43be4cb21f0efa3d66e2c5d0db0a1c27235e08496b81ec8414b3640222a7c56ae9c43e7bc9f52a5b18656511273785753deab1b352305ca7155ee18f41dd5a362c33bc500347d7cace4b70aea6c81ce9883371345195e939c606159b1dd9d19e9d377faa303047364', b'9b8ce0328d7e5f51241beb3c593c3db3bf1d17bb4d9ff2a5e0788963ed482432126f22622d6846b393abae0bb2943d8db667c5ecb95ad7e996465a0d2444fa674859603675e5bf777a25ac77f710389e830bd3aa2663927958c4b2', b'3a033e775985a1e16d3c77ce26bc86a652d752f35f7983c27c416f9f7f1a15a7d24ac3cd1012a6e5b7e8c3328d74e5e5bf9208d2a1eae6259a7d2431b52ec84a3eab13be667e48ad1b023be63491a5cada0a5641e63108febb1db4c16eb3a144d5cecac8', b'6bb61da0fbdb1d066d75b11ee30b1a15d3fe16ae1440dcb4d4be624609eeb43c55b8e05ae0d0f0d764aa056165b5e5fa104c89654b6973c691d74e27a062db00022774c1d962f511c9bd7226367e376475b02136f23742ca8a0b5475c26465bbe3e3eec28633cb90f2c611483692d44237', b'4a97c9e481df634c4299f65c59352c50871b8f5e6bca626e63b24606c8f1988fbec9d938830af19302813258ad870fe22a20ca4fd0fb71794ca8b40122672d5c1e4a1000b1948901132016177649fbf2c6f40c96694d94a2f596f5', b'9c8ad6731f17d7bfb8dff6739f526e598f7e88523869fe7f3c326835b65fa4579b43a343ca2ed65ba9110eccc8645595a35f781335f434a39f667c26ad0ef44c7fe6bfccda2dc6a99b02c73051ba948700d7cbaddfd96c280f50d12f5c96e1755a38a8c0', b'3156366f49d7b1ec6d3a32813cab86b155d150fb5f2accc43312749a730641e2bb0fc1db0357a3acbce5953fc469f2e5ad9106defabce21baa32252db50d941e38c714896d4324ed2a1806897786ac9893155a1cb23f46e5ee11a0c63bb4ac0f', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712f953a65ccb2ed85db00f0ecbd67810d1b75678193de4338ee821223f9715f24c2db0a0e0d142eef3991a956848b18c8700d7cbaddfd96c280f50d12f5c96e1755a38a8c0', b'9286932c84802a90bb36abd124f0a1f0c076265d14a1eed17f3eae8c8bee198d145f795a2f6f664ce19940f4f9831db7fd8e5f5e47695575179bff222d2a07c3724eee218f73929262d96ec74a3a027b909be61dbe6ad9d78f957e094a5c0a8b9c6b3252b0939e51ee9268eca306056324fc262b57b6', b'91135aa897cc7cf173e770d926f6cc00c95840aee34aa4ecf0dc2fd5fefbe641774ded4e5f69201dc68314579a03b380e86a2404f08c6ad03573c1f0cce76350a078322bfe47d09c4cc73d70514d47832ec742ef134bb14f9c9bfd63f9b48add13277a3fd7a897584e1b1d6c', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712fe50aa42d67ac95bab1a0eddce6346d0e5566f113ce42b9da6262836d213ef0962bbece7dc07b9f5811ed07201b080c31c98d1eb8bd0292b0817', b'921e1fe580da7ba531f275d52db5dd4f8a4742bcfd57e7f8bfdd2e90fdb7f0477f5db72128247408eb845c538f5feeffd24d1e17ed9d7b8f2b6e9cb2cafb7903b3792338ec18d6e36c9a786c2e5a40882f9758df0877ce1f939fe627e8a19e8e0a60', b'8ec4f577996151587f4def0269733cafbf3e4bef4bf3f592eb45e523dc52195d51782b3070774cba93bfa909ff9536dba4749ca1a85bddb99b0317033e46fe2c58092e276be5a4252e27aa65f6427999895fd9ba6870da7e53d8f52a947332b68670bbac582c2f9b72e530bb8cb6b82926', b'8a97da3f0b52dca3a2c3f66b80536e4e9c629a1f223db16e7d2f6937a710a8579b42a05eca2ed25aaa0842c081785fc1e55a77002bb62e89b8266d269a1fbc5968a7bffcda42eef29a56dc7301a786ce17df9eebc7d72b314a51e21c48d3fd4f4722be9cc1c843348edb347c0314c6426816d70ba31f', b'9296d97a5b51c2b1aad6e674b76b7a0c89449d572e3ba27e432f4807e05ebe408b56b64d8f67d212b2154fd081615595a85272116ead28d0e83321259303ef0965b4bfb3d607fcf4d956d46c56a290d459cfd7e1c7962e2f54', b'2c1e323b5fc0abfa383a3ecc34f2d2ad00c25fff422dccd17c4672977f550ca3810f9d8e554bb4eda9f7c33b8369aee58d960c95a9bfed15a32d35278f29d40f38f10d8428577bff120d79be1bbfecdbd73a5709f72c1bef911a97fa7da9bd538cccc09b4232d46d7c9f1dae', b'5fdfdca182d969511687f15d59323a489649d85b658e6e3d25b94808dda6d0a486dd8429a85ef4934b922873b0e827b92b74d10c80e5633043eff91c3e333f43141a5e03ab909c5a573a20252658eec3cbe8018d3459eba2dfbee8a581d7dd5564a9fa6f3135', b'8c5b57e983cc2fe936f26bda26b298009f4d5eeff956e1ada9cd3cc2e8fbe5486519ff0917752b5cdb9e5145dd01f4ced8222857a38468db3e3794e285b46318af67732ae916dfb82b9b53533a085bb9289c54c24e77b112bdb0bc3dfdbfc78d1e33373e9eac8d1649070227a9c7dd9b6e74fc', b'91135aa885cc7df63cfd39c32bb9981c88515fefe44aa4eeb1c633dfeffbf3452409b0101a303614db855852dd02f2d49c6b2f50e69b7bca2b63c1e6c1f13700a3662023eb57cfab74d36a686f5e54d634ab66844c70b1089a8afd60fa9299b2387d792e85f194015d540331fa83d4976161f228caea', b'8ec4f5779262434b2419ee3b582e6eae8c3e03fe51a9e8aaa563c930c64e0e4d456435796e7150a093a8a944f3992cd7f3618de4f858dea8901d070c0867af3d59267a3b66f2fe2451398a4da05e2d82ca0fc2be6876d7644993f537d33e23ac8665e2e8432735da79ed32a782', b'9c2880708f5e6abc0ebda6c82da626dd5908818428785598de4a97326bca20db5b8e0f1c6ba0bcf0ef3a7eba5d056116a29325567b7fa14714ecfd0abbd7f7b4305a9693d7f208e9d6da39008e26c47fc8eb13c9f05e58324ac97cb35a19d2b98fc006819794', b'87ce86698696378df42fe3c96cf1e4f5c47d75101cb1ab92783ca18484fe13b7630f2740153b7d41fcdf5fcfb7a22df0b393431a52625a2006cfb22d323f01d32706df13cd2794ed62c362d01d693c7ba6b0bd1aa47fc9c9939f70', b'849b9f6090c5218ca12aabc93bf1a1e7d36a34100ef5a1c03e23af8e9aa1158d145e7a472f6f624de2800cf8b09f17e3bb8b504d592b4f5f30dbee301e3f08dd3015c229d50db9fe78c5798509302035a6aba053be77c9c583813219024d429e906b3213', b'4297d8f587de6540179afb1314226955970acc5679dd273a6afe410dd2a68be081a2bf78ed0ac68218d73334b0973e9e1b67d60bd2b27c2050a8ad0038607617324a1000b1948901003309173206e8bccbef0b94274bdab5b084a3a880d6880b', b'b3648976820b228f3ce8e5d217b66ed75d5e80fb325f6f8bc95b8470689329936e924a4b72b0b7a3f43d74a75d017b16b2933b4d3432a95051abe713f990b1ac3e1d81c6cb8d32b8dc8e0f009563c124d49414f58f0a592f569e2cbe4819d5a589c306889bd7ead7f58633399c2bb63ee6d62a', b'8a97da3f0a42cba3b9c4b972c8553d53893b9e572469f7617d267c68bb6f9d068a529044c76bd301b62240ebfe255ec1b703690d33e4358fe835223b9c1dbc5d62f5a0f6c042f4ffce56dc7452e39ecf1698d7fe8bd12323145e9d3f13c2fa645c3afb839795', b'8a97da3f0a42cba3b9c4b972c8553d53893b9e572469f87e3c276b39b44bfa5ae471fb01db51d55aa00f1dd7fe787feaf65d6d067eb42581e835223b9c1dbc5d62f5a0f6c042f4ffce56dc7452e39ecf1698d7fe8bd12323145e9d3f13c2fa645c3afb839795', b'8c5b5efc81db66e726e77c942eaf981c9c4b4faafe4da4ebbcc93acbabb3ce77305cab210b78200e87836b58b233aecec8707154fa9429cb343795fac0e72d508f343d29f312cae37c927a612e565dc6289b5edb5d658005d28af730fcbe92d3', b'01a4f4a5529983d0dd02abcb0ba0aae045feaec5168003ace36aaa812e855b7d90d9545d5e62f225cec76653d5cb36d181e1039e17c8ff558e4628bb0fbfad077f6ebccbf2d59ebd71cc68be60e7c6b324920097b10784920423dc9a48698a9df97e0f269c1262399edaa5960a2eb23d86ef592b', b'8a97da3f0b52dca3a2c3f66b80536e4e9c629a1f223db16e7d2f6937a710a8579b42a05eca2ed25aaa0842c081785fc1e55a77002bb62e89b8266d349e1bfb523dbd93c48053edc5811ed07212b0b6c936e78de3dfc47c3a03449d3f1487a9605638a8819c9b6b32aea46e615702995b7f0cd70ba31f', b'3956277e4fd6b7e038283bc036a996aa7fe507af580698d839403381451b349dc141dbcc4542a8f1fbf38b35c468e5b3bc8c49d8bbbeeb5aac69782c992ec14429b80e847e5465be010420b320c8b984da114b08fc3908f2ab03f6', b'0faea1e8448b99d0d106b1cf17e3acb24ce1bc8219d80ed3db3dfe941fd1467696834b224942d836c8d2620685c62394c2e8018c00daac48be646faa188fb71c6f71ffccc4d4bfc235cb68a470f4d0a07792068db615c3944527dace456a908bb423', b'7bbb1ee9f8dd1a172373ad00ae0b1215c2f30ee91f15db9befef73553fecb97952fbb371e6fac6962aae182670beb8b31319996c046e7e8f96cf073daf278f1b133f26d1df62e611d1b36d2d623f367b7bf12b36b3315a928b3175249e7554bba5', b'4297d8ecd3ca60430595ae5b260c7d179636db5b6fdc343d5ab0683e80af84a2d98d9131fc10f68250d36177b1a734a427209810c6a261200debb01a326621440f0b1006a282d5012e721e1f3208baeccdef008a645e94a3f6c1b6b2d5c1884674a7b36d3a6881', b'76fe1eecf7d3154225498947bf102b41ccfa1dbd177add8be7e82c5512a8a1655de8a447ecdbed8522bb037a20b3adf643188e6f1f333be6dfd6523ab362c90712303085873cb111d6bd7d30366b363d3fff6733e7704e888d3a646f', b'800d5afa8cdd67ec3df439cd2ca3ce0ac94d5aaaff1ef3ecbedc38d4bbb2e2006b03ff181371220784986b61c95de9ffc86a2456b09a56d11448d2fcdde62700bf697338ed1298ac6f9b69762e4a468239d45ed65d628b1d80c1', b'1e1a367c4695b0d14f7a66d50ea6cea7528140c14216b383324672c26a0c06e2bb0fcbd7115ca5acbde58a36c472e8a0f98a0cc6aef4ae33ed2360369e7ac64039f604c1390127be021730a5649cb7cac70a0308e67e5feea11abf8b', b'7aa81df2efc0061b2371fe0ae111025084fa19eb1605c4a5d6af274540f1a23c4fa6e05ae0d0b9ca30b20f6420b4acf7064c847a4b7b77ce98c7172198159b59130120cdd37eb242feb24b1c25712d6f6be03e27b3365c9b907a', b'e55c791de7d964cb36f472d350e0e9b5530ebde103a675da81b0d226074d4f65389e8eac823914d08ad4e23a27c4018de8ae4ccb032be685d98d6d0accb80d87f89469aaf44679117f05c88eb089036d2b6a0242070f48d2904aa618a3283d0e680b1cfaaf1f', b'49c2d0ed978c754d179cbe5c0e356942900cce5e798e683c25ad480cd6ae9eb5c998843fb95eee9f1cde616faaba35f12238d918dbb264067abce81c0e67245209590d3aa9bea41209260d426210e7bcc6ef11df734594aee588b7afd5d1854074a6a92c', b'5fdfdca19cc2605b429efb410a3427069b06da136bdc626e61bb5415daaf95b4c989876cbe1bfa991dd7616eb0e836bd2533c34fc8dd5b6d1cfc861c39763e040835102a98c2955515620f0b6f49eef4daa0149a7559dba2b098b4bed5c1884674b0bf2220748f447022', b'2c1e323b4dc0aafd772077d639bd86b141cb40be452dccd33d5c6e9d6e5519a7d24bc0d01012a2e4b4f18f3ec468efb1f99707c1bfa8fc0fbd3d3523863bc7547cf03fb63c0063c1011e2ca4779b8784ec3a100fe62c18ecb709f8d126a2e951d9ceca890c7bd0257dd003f3c1511c5a5db0a3e6186a', b'0ca3e4a55e9681899317b8dc0aefa7b253e2a8c5039a03ace86cbc9429cb4b77c4c4575d4161e662dd967869a28b6fc0fef3079a0280bc62bf5e43b91594ab5f6a65f298cfdeb28d2fc73ca523b7cba661d11f87b1158c99042edccf04629c9bb0690361800962349dd4', b'00bc0307860daee607636ce345afefad31c2ff71aa636e014b3713c99bd6f4dbf50e9f656413af3a19a70c97ea8b8508719d679a4e751fb522fc5cde76cd976d5c35473512adc8a32719a2e2f5cd512587daa2e9ce222761fa850ef20c316277f3c2a06e57bcab431c0d4ef20eb2762657ad49', b'4ec1dcf38ad8644b0c89be4a162e3f43c20fc3526dd537265a891350c79e84b88c8fdb3f8310d6a943dc3575f3b829ac6431ce1ad2a27b3843fcbc0c717a3f1714045e11af94db4e133a1a00321af3f8daa00b99274cd1ade2cf', b'bf2d957f911c22942be0e3d952a121d54e4f9ab228502adcdf4c916a3bd5319a689d5a544582edb2ef0c65bc181e210b89dd1d612731bc4604fbeb1ef5c2b2a13b13949183bd17ac89957007926bd663cfa214ddf04e582950c67cb04750d5a48ed708', b'66b10da0f5d500522373a816fc441747cbec1cae104dd6e4d7b827400eb8a47254a1ac0ef1daec852cbb1c7320a1a9f20417db74344a2f9e8be35321a2309c1b38301bfa8562f54391ac7d3e366b31787bf3282fe1315e9fc2206c619f7f49aaabf5f5969d1885b0cbd50b542182d753257650a5', b'7ab70ce8f3c64e053f7faa16ae171b58c1eb07e70a4293b3d7a9364940eab47d44a1ae49a8daeb8520b54a706ca6a2e85304b44b5f2c6ff08bd4423bf431f006280167cbc27eb141d8a1243079723c6933f9293db3275688963c233681794ea6e5e1b2', b'4a97c9e481df634c4299f65c59352c50871b8f5e6bca626e64fe410dd2a68be081a2bf78ed0ac68218d73334b0973e9e1b67d60bd2b27c2050a8b40122672d5c1e4a1000b1948901132016177649fbf2c6f40c96694d94a2f596f5', b'66b10da0fbd517522f73fe17e7171545d4f006e01040d7e4d1bd62580fedf17a41a1ac02a8d7ecd164a3056320a6b7f64308847306787f8f96da0730a8378f0e0b3f33de8664de6695ed701c62773c6f68e31834dc0f0a94962633318a6d1aabe4e8e8d1811edcf1', b'91135aa89ac763fc73e37cc630b9d64f904759efec4ce1adb4cd2ec4f2b5f4442419b05e1d752613d995145f8e4ce9c8d9223141f19a66d17b6e8ee789f07213af70366ce31bd9a460c3645b590d1e92038059d50f379d239ca0d060e7b985cd17376a7a83aec41a455a', b'938cf13adf635f4b241ca72d4c2869ae833e03e55fe0ebb4a569d362d153061e55603873786b11eefafca709b29b788ba17a81f4bb4a92af9b07501f6758c45b19487a0c77e8a8253d249a7cdc6f6a9e8e0d8bb3317992785b93f13dd33723bd8a7af2a7593175', b'a082976b8fd530bc836cbad213ebe9e6d33c2622139a91817024b2d38fb706c8751b62463f236c04fc854ff8f98013adfd8e420a4d7542201087b037246b03d02b4ad504de2cc6bf63df2bdc173d3235b7ada653ab6a84d4d69f36184c1942928a39295cb0d79a19e0c064bfe60f1a7e33b5', b'8f88d6759b907887bb78edca2df8fab3c95002494ca191c67635b2d08c9115a76b087840387f655df3cc5bf8b89952bab292474f027a4b770696ac6425240edd6e06c819ce2e8aed71d47f950e213c61ffbdba06bc7dc9c69a9f3f0451194d948d6d2453f0', b'0ca3e4a557948c97c857b5f12eb4f8e675f9b58010db15d3e24690d32ed15c2394c9455d5768f576c9c830419dd07ec7c0fe1cdf19c7ef5eb07f72e50fc0bb0a3a78e0d6c89ba28a2dd770a870f9d0ba24980196a6149182542393ce4c63d988bc7f152e9a46353e97dab88d4f6aae3c87fa1c6c0ec5', b'899a9f720e44daf0afccba7d865f2b1d9e74874c3b20f27873347478b05fa441ce4bbf44c661cf12b2145acc81705cd4a248291c119368cdbc0d393a9708af5a52bb83cc870cede8c506cc7d01a086c90adbd7e2dec56c291b49d43f1d8ee0635e64', b'a082976b8fd530bc836cbad213ebe9e6d33c2622139a91817024b2d38fb706c8785270516a266604f9844de4f99a17e3b0865a4f0272532c478eb333203213982a47c256d92783a33a916ad90e282466ffb3bc1fa6388bc2d8', b'828b90659a8c2c86ba3df8d56cf9ede2c67465152282fa836a0fb48b9abc489b6b55596b79216156be9c55edf98214e3ad92435a4d6842200e9cff30292e40cb3647c302d22c81ed66de62db0d693273ffa5b91fea798acf9f8d28184f5c448fd7', b'9a9ad976155edab5a3c8a56fc853281d8d6e9b4f243af42d7532272cbb55ea41cf47bd44c660c612b51247cad53656d9a4546244269b0bc8f92612269a1fee1a7e8aa2dceb51f7ee8746c5795ce386c159d9d2e18bd72f22135ccb2e1187e7641d', b'3c13317253ccaceb762b24d271bdc0e250c741ee432a89903541208672105bb1864eddca1c5cb6acabeb8a349026efa3f99f05d9fabce21baa32252db50d941e38c714896d4324ed2a1806897786ac9893155a1cb23f4bf4a711aec023a2a75592', b'5fdfdca19ec37f56428df15e143427069508d6137acb683e69bb0706dab795f08f91892ba74ef1a9278670739cbc38b43667cb20cecd536a43fcab58216a31170e1a5e11af94925347221005771bbaf5cca00686275edca5fe8ab2a59285994d78adfa663b75db067d6d0e93230e7f2cf7', b'97dfde725b59c1a4edccf66c9a532a489e6fc9502d69fc743c226e2ab045a741cf47a153ca7d8f128c5d4fc981705cd4a248291c119368cdbc0d393a9708af5a52bb83cc870cede8c506cc7d01a2c9d70bd7daf8c8c26c251c19d0325c86ec735a39b2819cc832', b'91135aa884dc6af627fa76da63b0d40e8e531ca7d269b0bca4f729d8fea9a2535b0390214c7e310e84804d4bdd05eecec822364cecc960cc7b708efbc7f33704a9343f29f157d5a620d365707d19588e33d458c35d6381159c88af27e6ed8489083e373792ef', b'52d8cca190cd62020c8be8560b7b2a548d1adc137ec6626e6abd4200dde185be9d94846ca511ecd618d33762e3bc38b46437d70ad2e36b3c0deeb50936687c5f243d4a54b3ae8f4902204c014d07d5c38cee108d375acdb1b095b4eb99ca9e403da7b3653c6f8f49732c0c9e664f623db68f7b61', b'2c1e323b52cbb4f7383e32d322bdc8e259dd46be4d2b899038577386731b1ea6d25bc09e135eb0eba0b48b05b332b1b1868a01d0a8e9fd25a3064a76842ed21f3ce11dc16a5474f1181369bf37c8ac82c6455304e02d47f2ee0db7d06ea3ac42d5d8dcc61634872f77de', b'66b10da0fbd517522f73fe15e205134e94f730d95014c79bccb3275353eb8e726f97f340fcc7a9d53da74a7269b4a4e3130382721f787f8f96da0730a8378f0e06373889966ef44581a56b36367e2b787bf42835fe355dda8b3223389c651aabe4e8e8d1811edcf1', b'8f88d6759b907887bb78edca2df8fab3c95002494ca191c67635b2d08c9115a76b087840387f655df3cc5bf8b89952bab292474f027a4b770696ac6425240edd6e06c819ce2e8aed71d47f950e213c61ffbdba06bc7dc9c69a9f3f0451194d948d6d2453f0', b'e55c791dfbc372cc62fe72d01de6f4fb504fa2ad12a4619a858aa5745a58776a6093a3c8c5570ec0a18fe93c66872e9adad108cd1879bf8680972204cba948d3e2c425bbe8037d066455ce8da6db546c376a0948071c4fd29046ef02ab283a1262021cf3a55f0bc6b690f33a1b264fa0cb', b'1bf906039d0aebf8427676ec54eba1ad3387ea34aa7f624f557205d38982a0cafb0f9f656d18b53a1fba4997a58b89127cd06b9a4e7253a32ae908d35bfcd6300819472f18b49ef01711cdd1b3c04e7997ccb7f58934766dc0f24fb3544e6277ffc3b37961bf8d72461052e54de2693e', b'a082976b8fd530bc836cbad213ebe9e6d33c2622139a91817024b2d38fb706c8785270516a266604f9844de4f99a17e3b0865a4f0272532c478eb333203213982a47c256d92783a33a916ad90e282466ffb3bc1fa6388bc2d8', b'0ca3e4a55e9681899317b8dc0aefa7b253e2a8c5039a03ace86cbc9429cb4b77c4c4575d4568e46acbc3305f869f2adcc4a71f9a02c0a053f16873ff5b86b50e7d67bfd0f2ece5d336fd68a435e58cbd5b9f20bdf00897851427cac704629c9bb0690361800962349dd4', b'9b8ce4258a61491f7614e4351e2a6cb5c02350aa56aee3edf262d563d7060805486d326278761fbcc6b2e60dfc8e37dbbb7c96a1b94cdfbad7115f013910f3655e5966326de4be776f25a032f55c3897814fd39c1f30836362c7f421816035818d46c4fb5936298b6afd3bfec9baa6247157', b'5fdfdca183c97e510d80be44113469558310dc1363da272d64b0490ec7e192b5c9998722b95eea9e1fc72d63e3ae3cb0232f8817ffd5386859d7ad0034617f442404313af49f8f535722060f3207f5e89fe90a8b6258c6b9e095fbbf9dc0cd5578a6a96d3a3bd84e7a2c1185230b7e3cb79a3e2614f7', b'9f81832c978436c3ba3dfdc33ebfe2f1ce7c265d09bdab927133a58291ee0e8640527a1433206004e68d5af5f9991aa6fd845e5f507a4065479bb0642d2413dd6240dd17dc39d6a549e63f840d16297dbab6e6009576a6f8c5862a0f12495386d96a285ab6c7c956e79275f7e642196225e9636c', b'00bc0a0bd006e1fe42633eeb4caaa8b977cfd206ea3a7f7e463a17c9db85dfdddb258c7c7804f16a0fb44994b889881376c92e8608331ead65e405c44aefce2f5c0b5d3e12acd5f031578cd0e6c20527c5c5bfe18d3b666af98516fb0075737cf3c2e96550a2ec', b'0fa3e4f1599d9fd0d50bbcc902b0a1cd7db9ec913d9c0ee9fe3abcbf2eea71208ac44a4d5774fa25dfc9651681d737dacaa716900593ac5cbf3173f85b99b61a3a68e7d1c3d0f19b2dd73caf31f9cbe224880097b103c3854d30dbce0a', b'5fdfdca19cc2605b429efb410a3427069b06da136bdc626e61bb5415daaf95b4c989876cbe1bfa991dd7616eb0e824b92174de13c1e5776945d78e5c60671343130f0c56b4ae956e386111066059eae5c2a0149a7559dba2b098b4bed5c1884674b0bf2220748f447022', b'9fc5e43f9a7f10487614f3381e3462b6853e4be357a7a6baea78ce7892540e0c456838773d774deed7b3e617fd973d8fbb7c8be6f849ddbb830e17023b51fc771d11510437b1b9087a3fa060a043069eb52088ad3c76826744cebc33813a32b78d6eb5', b'8a97da3f0a42cba3b9c4b972c8553d53893b9e572469f87e3c266831bd57ea46d406a355db2ec75ea41a5594c9496781f447460026a12ecfbb0d231dad49f25d7fe5bceac942f4ffce56dc7452e39ecf1698d7fe8bd12323145e9d3f13c2fa645c3afb839795', b'52d8cca19ecd7502008bbe57102828569206c65d7ecb636e6cb80718dcb4d0b6859c8f37ec16c6a144833558b7a035a37727e711efdd3f3759fae918286e6c511a031249e7938e55472b10073208e8f99fe40b906a4fd0ecf987fbb29ad0cd4172baae222069d608', b'8a97da3f1658dda4edceb9718553201d8a7a901f3b2cfe7d7024273fba46af12ce56ef44c76bc840e50d41d3c46410dcb6137b0d6eb03495a639243c955ae84168acecf5d803fee1c51eea5715f29df80dd0dbff98c5132435668e250890b9604a37fb8a9dd5687aa9e571775707984b3f', b'73b71ee5b6dd1d523a7ebf07ae131115c9fe04eb444cc7e898ba2e5601e1a23c48a9b30eead0fccb68fa0b7a77a6bce0430a877d0c662bc7a0eb1378b31ddb00022c67d6e962ce6e92b27031266f20607be72e36ff705b9fcc', b'8790ca3f1856c0f0a3c8a0799a1c2d4f92689a1f3f21f42d73226239bd10bf5ccf4fa310d661d412ad1c58c1816258d0e555751529bf6c94970579638625e84168a7ffe0eb0cd6c5c618c17211b390da59dbd1f8d9d72b2f5a4dd26b108dfa751339b2899acf3c35a7a4737a1246855a7e19924c', b'b3648063801c6b812cfdf29c1fab6ecb5e5891be35442adfdf1e916a72c067db46c604596cb0aba3fc3267b15d036058a2dc3d55343ea64d14edfe02b2cbe7a8002dcec7d78d11e488886307a268fc4894a50ec8e0494e2604cb24a4404ac4e3', b'8ec4f5779262434b241ee830532863fb972b5aaa49a5e9bde96f9a77db500e4d476d377766285791e4e8f710cd8e309ea12696deb671edfa991245542749e62c58092e276be5a4252e27aa65f6427999895fd9ba6870da7e53d8f52a947332b68670bbac582c2f9b72e530bb8cb6b82926', b'4a97c9e481df634c4299f65c59352c50871b8f5e6bca626e64fe4a08c0b591bb8cdd8629aa1bebd604c02862a7e836bd2533c34fc8dd5b6d1cfc861c39763e040835102a98c2955515620f0b6f49fbf2c6f40c96694d94a2f596f5', b'52d8cca190cd62020c8be8560b7b2a548d1adc137ec6626e6abd4200dde185be9d94846ca511ecd618d33762e3bc38b46437d70ad2e36b3c0dfcb6483d7c3f525b191702af85db4e01720b1a7749fcf0dee71fcf6f75e3f8a19584bf9dc09f166e8bb44d0b28c152673c088f7e4f623db68f7b61', b'3c13317253ccaceb762b24d271bdc0e250c741ee432a89903541208672105ba49e4ec8c5455a8edbefb59705906ee5b7ea8d36db9585bd14b93b25359327805c38f91295615f70be051920b830c8b78c83044f0db23f4bf4a711aec023a2a75592', b'3a033e775985a1e16d3c77ce26bc86a652d752f35f7983c27c546c937d0e4baaad789b8f016da5e4bef6d029bb68cf9aea901dc7eaaaf707ed3a7a288f35ce4a6cfd0c926d1160f7191a69be2d9abdcada0a5641e63108febb1db4c16eb3a144d5cecac8', b'5fd8d6a19ecd625b4288f2521e20794ebd3e9b027ef1732660ac1412ecafbf8fda939c3eec0ee08b50dd2727b6bb70b036319811cff62c3544feb00636332342094a1a17a290965247301a11731ce9f99ff701df6658d1ecfc88ada29bc2cd4a68a6fa64317add553b', b'9c144aa896c861a53df66fd131f6db1d865b5feff956e1adbfcb38d1f5fbe44e7004b35e067f305cdc914253dd18f5c59c612e51f1886eda7b638eb2c5fb6415e6673a2bed0398ac7dd36a686f5e54d634ab66844c70b1089a8afd60fa9299b2387d792e85f194015d541e2abfc7c8966074b76f', b'9c8ad6731f17d7bfb8dff6739f526e598f7e88523869fe7f3c326835b65fa4579b43a343ca2ed65ba9110eccc8645595a35f781335f434a39f667c26ad0ef44c7fe6bfccda2dc6a99b02c73051ba948700d7cbaddfd96c280f50d12f5c96e1755a38a8c0', b'9c8ad6731f17d7bfb8dff6739f526e5b917a8e447b21ce5a28707307a758af408855905ee051925cb10f1ed4d86b10d1b75678193de4338ee821223f9715f24c2db0a0e0d142eef3991a956848b18c8700d7cbaddfd96c280f50d12f5c96e1755a38a8c0', b'b893de780007c68f9a99e768b74826588f289a602506ce3e72357568a349b712fa06bb42da62d812b7144dcc817b51dbe55a6a5421aa39dcbf3a2221975aff4164b9a8e1d10cb9e8801895694fb7868711d1cdadcac421395a4ed52e12c2e179406ab38f9cdf6f7aa0f66232120b86466845', b'00bc0a12841ae7e817767bad4db2efb132c4ee34ad782b555d7206d38185ba93dd5ad1777a13b33a11a81f81ea899e4673d16f8e15231b8b12b35dc276eecb395a5940021990a4e316039f8db6da5877c3c5b4ffce2e287cbfc003e155627331', b'ad21c17a811d76c33be8fbdd1cb12b9848549ca8365e69dedf4b962278dc33887a8b1a4873bab7a3ec3a65bc5d0f7d16a5d03b51612ce85755fbfb17b4dcbeb33254da90cfb302f7dd920f23c937c748d3a31fc8e34a68356bf16fa9414b91bd99cd', b'97dfde725b59c1a4edccf66c9a532a489e6fc9502d69fc743c226e2ab045a741cf47a153ca7d8f128c5d4fc981705cd4a248291c119368cdbc0d393a9708af5a52bb83cc870cede8c506cc7d01a2c9d70bd7daf8c8c26c251c19d0325c86ec735a39b2819cc832', b'8a97da3f1658dda4edc9bf7a8e552d48916fc94b2320ff6a3c287478a758af12df43ac59dc67ce5ce5094184c0754499e54771116ea2309daf297d3aad2da818798ab8fbd110aae9aa18fa5f12ad9dd549c8c7f08bc429390e19d4385c8fec625626a2ce86de723ba2ed736b59', b'2f13777648d6acae7e2236c62ae2ce9d778602ea732d84d52e0173ad743a24f19c5bdd8e054bacacb9e58f3b8a65e5e5ba9107c6aab3ed0fa23c66658935ce5c39f51095615e79be021f3dbe648bb784d0064a0ee72d08ffaf04b1d12faba052d192', b'8a97da3f1658dda4edc9bf7a8e552d48916fc94b2320ff6a3c287478a758af12df43ac59dc67ce5ce5094184c0754499e54771116ea2309daf297d3aad2da818798ab8fbd110aae9aa18fa5f12ad9dd549c8c7f08bc429390e19d4385c8fec625626a2ce86de723ba2ed736b59', b'8387826491977894a631ffc36ceceeeec47b3d1413b2eec57122b48bdfbc1e89505278536a297945e9971cf886ba46f2a9b84542476914733881901b722514ca7256c80b9b2d94ed72de2bc616243861b7adbb14ea6f86d582807e0a50505e92977e6f', b'b3648976820b228f3ce8e5d217b66ed75d5e80fb325f6f8bc95b8470689329936e924a4b72b0b7a3f43d74a75d017b16b2933b4d3432a95051abf40fb4d7acf03725adc292a63af8859f22478e59dd58f8f814cea2094722598e29b71919d5a589c306889bd7ead7f58633399c2bb63ee6d62a', b'8a879069d48c2b8da078eac423eaf5a3c66a210914bba9927f3ea4c397af0d815a5c3a14233b6604ef8e43e5adcd15aaab8e5f4d027a49644789b325263050d01d718547cf1d92a573c338c62627124aecaaa101fa6890dad68a3b144c5e04', b'8c1d1ff19adc2fe13cb36edc22a29816865d5aaaad5fe8fab1d12e90fdb7f0477f5db72128247408eb845c538f5feeffd24d1e17ed9d7b8f2b6e9cb2cdfb7915ea342a23f01bd4e37c96782479514e927c8d5ec50b61ce1d9e98ee2afaed9092133a7234d9', b'2c1e323b5fc0abfa383a3ecc34f2d2ad00c25fff422dccd6305367892a1d2495c61edbe1015ab4fee8f7bc34ab59b3abad8c59c5a3a7ae1bed3d67208f7ad74e3fb852d1284872ff070569b72387f6caf70d4641e13b4bf3a010f8c72bb4bd01c8d5d4834232d46d7c9f1dae', b'921e1fe580da7ba531f275d52db5dd4f8a4742bcfd57e7f8bfdd2e90f8b4ff537100af0a167f2b5cd29c5551865cf5ffeb367050dc9d61da292492cdc7db4843a860217cf50ec5e36c9a786c2e5a40882f9758df0877ce1f939fe627e8a19e8e0a60', b'3ea7e0e24ac885afe453ecda26f4a1f758beaeba0ca739bfe27dbdd030dc5333b0d85d5d5678e276d2cf7f58d5d62ddad5a718971f93a64ef17673e31587f91b753ce3ddd99bbc87798275b823b7c8a66bd10691e3018c9e4a3093ce4b268a8cb67d462c9148', b'52d8cca19ecd7502008bbe57102828569206c65d7ecb636e6cb80718dcb4d0b6859c8f37ec16c6a144833558b7a035a37727e711efdd3f3759fae918286e6c511a031249e7938e55472b10073208e8f99fe40b906a4fd0ecf987fbb29ad0cd4172baae222069d608', b'6bb117a0f0d80f153626b62cd9504541fbeb07eb1616c09bd6941d120eeca32c50b1bd0ee5d4f7dc64b50c3675b4e5f21109cb7204693bc396ca4e27a062c01d157e30d7d36dec4281be6120776a2a787be7227af2225cda8e3d75289d771aa0fef4bc97900dd7ac83', b'891259edd5c07ca524fb78c063a1dd4f844947aaad57f0a1f0c931c7faa2e2006c0cac5e1d75201298d0525a9c0be690d45d1610b29d56cb337293a1dacb793f99273d38f747c8ba66d36d68795856957c8358dc11248c19dc', b'8c9ad27a1655cba2edd9be7d9c1c2052893b8e5a3f3df8637b617030b244ea4bd453ef47ce60d512ac0e0ec2cd7757cef55b46237af528a3bc3a2820c109c347428afffdc010a9ea8c0b95734eae8cd310d5dbfe8bd76c3d1557d92e0e84fc7c1339af9c9dd0797aaee2277e02059d1c', b'97dfd77e0d528ebca8cca4728d586e528b7e9b1f3f21f42d6524662aa010be5ada52ef47c76bcf12aa134bd7817b59dba11370076ea93d98ad723822de5ae84164a6ecf7dd0ff0f49c05dd6552e38fcb18dfc5bdc3e91b7e4b4de23f1487fb234015b5a1ad88722eb3b4776b0a4690577019d9', b'5fdfdca19cc2605b429efb410a3427069b06da136bdc626e61bb5415daaf95b4c989876cbe1bfa991dd7616eb0e824b92174c81ad2f163370df1b61d71772954120e1b45a19d9a461c62172d455dabe8e0f40c9a7519c793feae84f89bd19f156dada72220748f447022', b'3156337259cbacae7e2236c62ae2ce9d778602ea732d84d52e0173ad743a24f19c5bdd8e054bacacbde58a36c472e8a0f98a0cc6aef4ae33ed2360369e7ac64039f604c1390127be021730a5649cb7cac70a0308e67e5feea11abf8b', b'91135aa884dc6af627fa76da63bfcb019d085ba7e21ee2e1b1cf2680f384c6143519800a1775374fc7af5a79a25ff3d4ce32315dfec960cc7b708efbc7f33704a9343f29f157d5a620d365707d19588e33d458c35d6381159c88af27e6ed8489083e373792ef', b'8c5b5be191c77ba535f270d863a2d00ac95c49bcf910a4c4f0c228c3effbf74f7103bb5e4e20755cc3914d45dd18f280d86d614df7c97ecd347986bc89f27b11a16f6324da208cf26fac786c6b4b1c95039a7eef4e6a9a0ec29ff62e', b'8dc4f5239768421f7d12f27d4a2f64b58b6a5ae54ce0e0a1e46dc120da793c5910750964757d4dfdc083a82bcdc9368fa12595f8a51ed1a8994658167749f4790d0d663a6debed2e6122e571f25e2ddcda06d4b63a61926554d4f430dd', b'1e1a367c4695b0d14f7a66d50ea6cea7528140c14216b383324672c26a0c06e2a54a8fd30041a5acb9e58f3b8a65e5e5ba9107c6aab3ed0fa23c66658935ce5c39f51095615e79be021f3dbe648bb784d0064a0ee72d08ffaf04b1d12faba052d192', b'1df40e46811debf9166b71e300a2bcac3387fa39b12b6d4d5335098b80a9d787a50ee0666413b329059607ab95d58212678d7e9013331aa765e003df47fd8328474a5f3803ff96b5435784c9b583523fd88ab2e7ce28296cf1c25bf64f31656bf5c1a0675bff', b'948b9b6999873d91f42ce3c738bfefecd52f321809a1a7dc7970b78b9eba5b915b4e36432b216104e79f0cf6b58c15b8ed8f6e7d162a535f1387ba3672383fd60d798218cf30d6bd6fcc2bc616243861b6a9b000ea79c9d099863a18505f5f97d96a354fb1d88c19eed421f3f6010124', b'2c1e323b4dc0aafd772077d639bd86b141cb40be452dccd33d5c6e9d6e5519a7d24bc0d01012a2e4b4f18f3ec468efb1f99707c1bfa8fc0fbd3d3531823f804920f9079a385948c941473d893080bd9890167c0fdd011bf2ba06e8d537bae951d9ceca890c7bd0257dd003f3c1511c5a5db0a3e6186a', b'a3175eef8e9967da04a728c01ca2d00a9b1b5f90e371dbbebedc2f80eba2ec004804b91b5f79365cc3985542dd1bf880d1632a41a3807d937b768de5c8ed6450ae75206ce712ddad37d36d68795856957c8358dc11248c19dc', b'9b89da6d0243c6b9a3caf66587493858dd7e9f5a3969e66c7235623cf359b912d448ef56c36fc649f51571f3952744eab15b7c067db70392870d7e3c8608ac5974a8ece7dc07b9f5811ed07201b080c31c98d1eb8bd0292b0817']


flag = b'flag{'
c1 = bytes.fromhex(mainList[0].decode())

for i in range(0, len(mainList)):
    c2 = bytes.fromhex(mainList[i].decode())
    temp = xor(xor(c1,c2)[:len(flag)], flag)
    if (temp.isascii()):
        print(temp, i)
    
```

And if we run this script we get the following :

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img10.png)

So what we did above was we XORed two ciphertexts and XORed that result with "flag{". Lets say the C1 = "flag{........" XOR EN and C2 = ".........." XOR EN. Since there are only 11 possible nonces and we have 400+ ciphertexts, getting this sitation is pretty likely. Now C1 XOR C2 = M1 XOR M2 XOR EN XOR EN which is C1 XOR C2 = "flag{...." XOR ".........". Now "........." = C1 XOR C2 XOR "flag{....." and with that, we would get the first 5 bytes of the second message. As shown above, we would print the result if it were made up of ASCII printable characters and output that. We can clearly see parts of different messages. For example, "I did" probably expands to "I didn't" and with that, we got 2 additional bytes which could reveal two additional bytes of other messages if we updated our flag to "We must" and changed the index (mainList[0]) to mainList[61]. Like that we kept guessing and expanding our variable till we got the flag was more additional bytes of different words were revealed.

<p> <b>Flag :</b> flag{0h_W41t_ther3s_nO_3ntr0py} </p>

## Blecc

![Redpwn 2021 Writeup](/assets/img/ctfImages/redpwn2021/img11.png)

The contents of blecc.txt :

```txt

p = 17459102747413984477
a = 2
b = 3
G = (15579091807671783999, 4313814846862507155)
Q = (8859996588597792495, 2628834476186361781)
d = ???
Can you help me find `d`?
Decode it as a string and wrap in flag format.

```

---
layout: page
title: vsCTF 2022 Writeup
---
<hr/>

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/logo.png)

I participated in <a href="https://ctftime.org/event/1658" target="_blank">View Source's CTF</a> event (Sun, 10 July 2022, 00:00 SGT — Mon, 11 July 2022, 00:00 SGT), playing with a few school friends as part of the team "finishingEatingLah" (inside joke). In the end, we ranked 34<sup>th</sup> out of 635 scoring teams. The last crypto challenge looked tedious but with hindsight it was easy. I spent so much time on Level 4 of Egg Hunt but it was too hard :(

Below are the writeups :

<br/>

| Challenge | Category | Points | Solves | 
| ------------- |  ------- | --- | ---: |
|[Secure Grading System](#secure-grading-system) | Crypto | 487 | 21 | 
|[Art Final](#art-final) | Crypto | 478 | 35 | 
|[Strongest RSA](#strongest-rsa) | Crypto | 464 | 53 | 
|[Baby RSA](#baby-rsa) | Crypto | 452 | 68 | 
|[Hexahue Hate](#hexahue-hate) | Misc | 445 | 76 | 
|[Recovery](#recovery) | Crypto | 357 | 163 | 
|[Discord](#discord) | Misc | 100 | 409 | 
|[Feedback Survey](#feedback-survey) | Misc | 10 | 129 |

<br/>

<br/>

## Secure Grading System

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img1.png)

The source code :

```py

import string
import sys
import ecdsa
import hashlib
import random
from time import time
from base64 import b64encode
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, size
from secret import FLAG, get_report_content


'''
Grading system documentation (for internal use ONLY)

1. The school's grader team consists of 3 tutors and a professor.
2. To submit the final report, student first needs to pass Proof of Work to show they are not robots.
3. The student will sign their report (in text format) with their name and send it to the professor.
Professor will verify the signature and make sure the student is THE real student.
4. The student will then send 3 copies of their report to each of the tutors for marking.
Finally student will receive their scoring.
5. REDACTED
6. Combining these public-key cryptosystems mentioned above, no way the system will have any vulnerability...
Secure data transmission for the win! NO CHEATING IS ALLOWED IN OUR SCHOOL!!!
'''


# Utils
BANNER = '''
 __   __  _______    __   __  __    _  ___   __   __  _______  ______    _______  ___   _______  __   __ 
|  | |  ||       |  |  | |  ||  |  | ||   | |  | |  ||       ||    _ |  |       ||   | |       ||  | |  |
|  |_|  ||  _____|  |  | |  ||   |_| ||   | |  |_|  ||    ___||   | ||  |  _____||   | |_     _||  |_|  |
|       || |_____   |  |_|  ||       ||   | |       ||   |___ |   |_||_ | |_____ |   |   |   |  |       |
|       ||_____  |  |       ||  _    ||   | |       ||    ___||    __  ||_____  ||   |   |   |  |_     _|
 |     |  _____| |  |       || | |   ||   |  |     | |   |___ |   |  | | _____| ||   |   |   |    |   |  
  |___|  |_______|  |_______||_|  |__||___|   |___|  |_______||___|  |_||_______||___|   |___|    |___|  
'''

STUDENT_NAME = "jayden_vs"

ALLOWED_CHARS = string.ascii_letters + string.digits

def randbytes(n): return bytes([random.randint(0,255) for i in range(n)])

def randomize_report(report):
    for _ in range(8):
        rand_bytes = randbytes(8)
        rand_loc = random.randrange(0, len(report) * 3 // 4)
        report = report[:rand_loc] + rand_bytes + report[rand_loc:]
    return report


# Classes
class ProofOfWorkSolver:
    def __init__(self, prefix_length=8):
        self.prefix_length = prefix_length

    def generate(self):
        prefix = ''.join(random.choices(ALLOWED_CHARS, k=self.prefix_length))
        self.nonce = ''.join(random.choices(ALLOWED_CHARS, k=16))
        return self.nonce, hashlib.sha256((prefix + self.nonce).encode('utf-8')).hexdigest()

    def verify(self, prefix, answer) -> bool:
        h = hashlib.sha256((prefix + self.nonce).encode('utf-8')).hexdigest()
        return h == answer


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s
    
    def print_sig(self):
        print(f"Signature: ({self.r}, {self.s})")


class Ecdsa:
    def __init__(self, curve=ecdsa.curves.SECP256k1):
        self.curve = curve
        self.G = curve.generator
        self.n = self.G.order()
        self.d = random.randrange(1, self.n)
        self.Q = self.d * self.G
        self.recovery = None
    
    def sign(self, message: bytes, hashfunc=hashlib.sha256, resign=False) -> Signature:
        H = int(hashfunc(message).hexdigest(), 16)
        r, s = 0, 0
        while r == 0 or s == 0:
            k = random.randrange(1, self.n) if not resign else self.recovery
            self.recovery = k
            R = k * self.G
            r = R.x() % self.n
            s = ((H + r * self.d) * pow(k, -1, self.n)) % self.n
        return Signature(r=r, s=s)
    
    def verify(self, message: bytes, signature: Signature, hashfunc=hashlib.sha256) -> bool:
        H = int(hashfunc(message).hexdigest(), 16)
        r, s = signature.r, signature.s
        sinv = pow(s, -1, self.n)
        u1, u2 = (H * sinv) % self.n, (r * sinv) % self.n
        R = u1 * self.G + u2 * self.Q
        return R.x() % self.n == r


class Rsa:
    def __init__(self, bit_len=2048):
        self.p = getPrime(bit_len // 2)
        self.q = getPrime(bit_len // 2)
        self.N = self.p * self.q
        self.e = 3
        print(f"N = {self.N}")
    
    def encrypt(self, message: bytes):
        return b64encode(long_to_bytes(pow(bytes_to_long(message), self.e, self.N)))

    def decrypt(self, ciphertext: bytes):
        d = pow(self.e, -1, (self.p-1) * (self.q-1))
        return b64encode(long_to_bytes(pow(bytes_to_long(ciphertext), d, self.N)))


if __name__ == '__main__':
    print(BANNER)
    print("[+] System startup...")
    print(f"[!] Welcome to the super secure grading system, {STUDENT_NAME}.\n")
    powchal = ProofOfWorkSolver(prefix_length = 4)
    nonce, answer = powchal.generate()
    print(f'''Please solve the following challenge to show you are not a robot...\n
        sha256(???? + {nonce}) == {answer}\n''')
    prefix = input("Your answer: ")
    if not powchal.verify(prefix, answer):
        sys.exit('Goodbye, robot!')
    print("\n[+] Verification successful.\n")

    report = get_report_content()
    assert report is not None
    report = randomize_report(report)
    report_signed = STUDENT_NAME.encode('utf-8') + report

    print("[+] Verifying with Professor...")
    my_ecdsa = Ecdsa(ecdsa.curves.NIST384p)
    sig1 = my_ecdsa.sign(report_signed[:len(report_signed) // 2])
    sig1.print_sig()
    assert my_ecdsa.verify(report_signed[:len(report_signed) // 2], sig1)
    sig2 = my_ecdsa.sign(report_signed[len(report_signed) // 2:], hashlib.sha256, True)
    sig2.print_sig()
    assert my_ecdsa.verify(report_signed[len(report_signed) // 2:], sig2)
    print("\n[+] Verification successful.\n")

    print("[+] Distributing reports to tutors...")
    for i in range(1, 4):
        print(f"[-] Tutor {i}:")
        curr = Rsa(size(bytes_to_long(report)) + 64)
        print(f"Ciphertext = {curr.encrypt(report).decode('utf-8')}\n")
    print("[+] Distribution successful.\n")

    print("[+] I don't think you can forge it but hey, if you can really do so I will reward you the flag.")
    try:
        T = time()
        final_key = int(input("My secret key when communicating with professor: ").strip())
        if final_key == my_ecdsa.d:
            elapsed = 1000.0 * (time() - T)
            if elapsed >= 10000:
                print("[x] If you spend too much time the professor will know you are cheating!")
            else:
                print("[-] My system is broken :(")
                print(f"[-] Here is the flag: {FLAG}")
        else:
            print("[x] Seems I'm right, it is super secure!")
    except:
        sys.exit(f"[x] Bad hacking attempt!")
        
```

Hastads + nonce reuse. Solve script :

```py

import string
import ecdsa
import hashlib
import base64
from pwn import *
from Crypto.Util.number import *
import itertools
from tqdm import tqdm
from sage.all import *
from math import lcm

debug = True
r = remote("104.197.118.147", 10140, level = 'debug' if debug else None)

ALLOWED_CHARS = string.ascii_letters + string.digits
keywords = [''.join(i) for i in itertools.product(ALLOWED_CHARS, repeat = 4)]

def solvePow(op, check):
    for pk in tqdm(keywords):
        if hashlib.sha256(pk.encode() + op.encode()).hexdigest() == check:
            return pk
    print(f"Error, could not solved POW :(")
    return None

r.recvuntil('sha256(???? + ')
ok = r.recvline()
op, check = ok[:16].decode(), ok[-65:][:-1].decode()
powAns = solvePow(op, check)
r.sendlineafter('Your answer: ', powAns)

r.recvuntil('Signature: ')
sig1 = eval(r.recvline().decode()[:-1])
r.recvuntil('Signature: ')
sig2 = eval(r.recvline().decode()[:-1])

print(f"{sig1=}, {sig2=}")

def parseRSAPubKey():
    r.recvuntil('N = ')
    n = int(r.recvline().decode())
    #print(f"{n=}")
    r.recvuntil('Ciphertext = ')
    base64_message = r.recvline().decode()[:-1]
    #print(f"{base64_message=}")
    ct = bytes_to_long(base64.b64decode(base64_message))
    return n, ct

n1, ct1 = parseRSAPubKey()
n2, ct2 = parseRSAPubKey()
n3, ct3 = parseRSAPubKey()
print(f"{n1=}, {ct1=}, {n2=}, {ct2=}, {n3=}, {ct3=}")

def low_exponentAttack(e, c):
    """
    Recovers the plaintext from a ciphertext, encrypted using a very small public exponent (e.g. e = 3).
    :param e: the public exponent
    :param c: the ciphertext
    :return: the plaintext
    """
    return int(ZZ(c).nth_root(e))

def fast_crt(X, M, segment_size=8):
    """
    Uses a divide-and-conquer algorithm to compute the CRT remainder and least common multiple.
    :param X: the remainders
    :param M: the moduli (not necessarily coprime)
    :param segment_size: the minimum size of the segments (default: 8)
    :return: a tuple containing the remainder and the least common multiple
    """
    assert len(X) == len(M)
    assert len(X) > 0
    while len(X) > 1:
        X_ = []
        M_ = []
        for i in range(0, len(X), segment_size):
            if i == len(X) - 1:
                X_.append(X[i])
                M_.append(M[i])
            else:
                X_.append(crt(X[i:i + segment_size], M[i:i + segment_size]))
                M_.append(lcm(*M[i:i + segment_size]))
        X = X_
        M = M_

    return X[0], M[0]

def HastadsAttack(N, e, c):
    """
    Recovers the plaintext from e ciphertexts, encrypted using different moduli and the same public exponent.
    :param N: the moduli
    :param e: the public exponent
    :param c: the ciphertexts
    :return: the plaintext
    """
    assert e == len(N) == len(c), "The amount of ciphertexts should be equal to e."

    for i in range(len(N)):
        for j in range(len(N)):
            if i != j and gcd(N[i], N[j]) != 1:
                raise ValueError(f"Modulus {i} and {j} share factors, Hastad's attack is impossible.")

    c, _ = fast_crt(c, N)
    return low_exponentAttack(e, c)

randomizedReport = long_to_bytes(HastadsAttack([n1, n2, n3], 3, [ct1, ct2, ct3]))
print(f"{randomizedReport=}")

print("-"*105)
print(base64.b64encode(long_to_bytes(pow(bytes_to_long(randomizedReport), 3, n1))))
print("-"*105)

def solve_congruence(a, b, m):
    """
    Solves a congruence of the form ax = b mod m.
    :param a: the parameter a
    :param b: the parameter b
    :param m: the modulus m
    :return: a generator generating solutions for x
    """
    g = gcd(a, m)
    a //= g
    b //= g
    n = m // g
    for i in range(g):
        yield (pow(a, -1, n) * b + i * n) % m

def attack(n, m1, r1, s1, m2, r2, s2):
    """
    Recovers the nonce and private key from two messages signed using the same nonce.
    :param n: the order of the elliptic curve
    :param m1: the first message
    :param r1: the signature of the first message
    :param s1: the signature of the first message
    :param m2: the second message
    :param r2: the signature of the second message
    :param s2: the signature of the second message
    :return: generates tuples containing the possible nonce and private key
    """
    for k in solve_congruence(int(s1 - s2), int(m1 - m2), int(n)):
        for x in solve_congruence(int(r1), int(k * s1 - m1), int(n)):
            yield int(k), int(x)

def hashMessage(m):
    hashfunc = hashlib.sha256
    return int(hashfunc(m).hexdigest(), 16)

STUDENT_NAME = "jayden_vs"
report_signed = STUDENT_NAME.encode('utf-8') + randomizedReport
m1 = hashMessage(report_signed[:len(report_signed) // 2])
m2 = hashMessage(report_signed[len(report_signed) // 2:])
print(f"{m1=}, {m2=}")

ec = ecdsa.curves.NIST384p
n = int(ec.generator.order())

r1, s1 = sig1[0], sig1[1]
r2, s2 = sig2[0], sig2[1]
print(f"{r1=}, {s1=}, {r2=}, {s2=}")

tl = attack(n, m1, r1, s1, m2, r2, s2)
possibleNoncesKeys = [i for i in tl]
nonce, privateKey = possibleNoncesKeys[0][0], possibleNoncesKeys[0][1]
print(f"{nonce=}, {privateKey=}")

r.sendlineafter('My secret key when communicating with professor: ', str(privateKey))
print(r.recvall())

#b'[-] My system is broken :(\n[-] Here is the flag: vsctf{Buff1ng_PuBL1c_k3y_CrYpT0(Gr4phy)_15_St1LL_1n53cur3}\n'

```

<p> <b>Flag :</b> vsctf{Buff1ng_PuBL1c_k3y_CrYpT0(Gr4phy)_15_St1LL_1n53cur3} </p>

<br/>

## Art Final

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img2.png)

The attached files can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/tree/master/assets/ctfFiles/2022/vsctf2022/artFinal" target="_blank">here</a>. 

Source code :

```py

# Teacher, please give me an A
import random
from PIL import Image


boring = Image.open('Art_Final_2022.png', 'r').convert('RGBA')
boring_pix = boring.load()

spicy = Image.new('RGBA', boring.size)
spicy_pix = spicy.load()

# Add SPICE
for i in range(boring.size[0] * boring.size[1]):
    x = i % boring.size[0]
    y = i // boring.size[0]
    rgba = tuple(random.randbytes(4))
    spicy_pix[x, y] = tuple([bore ^ spice for bore, spice in zip(boring_pix[x, y], rgba)])

# This final is HOT
spicy.save('ENHANCED_Final_2022.png')


# oh shoot, i forgot there needs to be a flag ._.
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode

key = bytes(random.sample(random.randbytes(16), 16))
iv = Random.new().read(AES.block_size)
enc = AES.new(key, AES.MODE_CBC, iv)
flag = b64encode(iv + enc.encrypt(pad(b'[REDACTED]', AES.block_size))).decode()

print(flag)  # Tl5nK8L2KYZRCJCqLF7TbgKLgy1vIkH+KIAJv5/ILFoC+llemcmoLmCQYkiOrJ/orOOV+lwX+cVh+pwE5mtx6w==

```

Solve script :

```py

from PIL import Image
from mt19937predictor import MT19937Predictor
from Crypto.Util.number import *

boring = Image.open('Art_Final_2022.png', 'r').convert('RGBA')
boring_pix = boring.load()

spicy = Image.open('ENHANCED_Final_2022.png', 'r').convert('RGBA')
spicy_pix = spicy.load()

#https://github.com/kmyk/mersenne-twister-predictor
predictor = MT19937Predictor()

for i in range(boring.size[0] * boring.size[1]):
    x = i % boring.size[0]
    y = i // boring.size[0]
    t = tuple([bore ^ spice for bore, spice in zip(boring_pix[x, y], spicy_pix[x, y])])
    predictor.setrandbits(bytes_to_long(bytes(t)[::-1]), 32)

#https://github.com/python/cpython/blob/v3.9.0/Lib/random.py#L283

ok = predictor.getrandbits(16*8)
t = long_to_bytes(ok)[::-1]

def _randbelow_with_getrandbits(n):
    "Return a random int in the range [0,n).  Returns 0 if n==0."

    if not n:
        return 0
    k = n.bit_length()  # don't use (n-1) here because n can be 1
    r = predictor.getrandbits(k)  # 0 <= r < 2**k
    while r >= n:
        r = predictor.getrandbits(k)
    return r

from math import log as _log, exp as _exp, pi as _pi, e as _e, ceil as _ceil

def randomSample(population, k):
    n = len(population)
    result = [None] * k
    setsize = 21        # size of a small set minus size of an empty list
    if k > 5:
        setsize += 4 ** _ceil(_log(k * 3, 4))  # table size for big sets
    if n <= setsize:
        # An n-length list is smaller than a k-length set.
        # Invariant:  non-selected at pool[0 : n-i]
        pool = list(population)
        for i in range(k):
            j = _randbelow_with_getrandbits(n - i)
            result[i] = pool[j]
            pool[j] = pool[n - i - 1]  # move non-selected item into vacancy
    return bytes(result)

key = randomSample(t, 16)
print(f"{key=}")

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode, b64encode

ts = 'Tl5nK8L2KYZRCJCqLF7TbgKLgy1vIkH+KIAJv5/ILFoC+llemcmoLmCQYkiOrJ/orOOV+lwX+cVh+pwE5mtx6w=='
b64d = b64decode(ts)
iv = b64d[:16]
print(f"{iv=}")

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(b64d[16:]), AES.block_size)
print(pt)
#b'vsctf{1_gu355_R4ND0m_i5nt_tH4T_5p1cy}'

```

<p> <b>Flag :</b> vsctf{1_gu355_R4ND0m_i5nt_tH4T_5p1cy} </p>

<br/>

## Strongest RSA

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img3.png)

The output.txt file can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2022/vsctf2022/strongestRSA/output.txt" target="_blank">here</a>. 

Source code :

```py

from Crypto.Util.number import getStrongPrime, bytes_to_long
from sympy import prevprime, factorial
from math import gcd
import random

from secret import FLAG

e = 0x10001

def getStrongestPrime(nbits):
    while True:
        p = getStrongPrime(nbits)
        delta = random.randint(0x1337, 0x1337 + 0x1337)
        pp = p - delta
        ppp = prevprime(factorial(pp) % p)
        if gcd(ppp-1, e) == 1:
            return p, ppp
    
NBITS = 1024
p0, p = getStrongestPrime(NBITS)
q0, q = getStrongestPrime(NBITS)
N = p * q
m = bytes_to_long(FLAG.encode())
c = pow(m, e, N)

print(f"p0 = {p0}\nq0 = {q0}")
print(f"N = {N}\ne = {e}\nc = {c}")

```

Solve script :

```py

from Crypto.Util.number import *
from tqdm import tqdm
from sympy import prevprime

p = 163753477176210014003355280732229891908166074468271556144642666169325605017666799921295576722168608401188682320182653287668989748162506955989407213845500704903463544753049275828138559289189335596749709834289278256382427251831790026921563375111737350084174473833546767952081017613072491759534988253353621530923
q = 157598184809589313845990455272198459548591786211953253450211152128535343234857067521711590445365424087430728267491317690639227988484930088637483194045435135802590588269993794073236513557034321374876808546159597997280236993358749182432517011554239468502233558179815446959403076134284375214662245037202945590183
n = 11884142558095727641000594156833818117849240126500615037738361957005811068956622520280143210434649198031005585252791693777710458190732464123269660559382653636999601459113099276826723072914352276709761755328542359490331355061792823458149611674845846523699218971126655186522340818792078719216860046464292413878045842425132308544311887062610272360069819975798905665533964761527225558339025724872067751916657135473510775709503714808686565298632040214249698116863336246844759838665285888816202570667521796553678688293761589082062045634768520102235077364345013564344229095323239077977717497503322831684471959195555281580807

#https://stackoverflow.com/questions/9727962/fast-way-to-calculate-n-mod-m-where-m-is-prime
def factorialMod(n, modulus):
    ans=1
    if n <= modulus//2:
        #calculate the factorial normally (right argument of range() is exclusive)
        for i in range(1,n+1):
            ans = (ans * i) % modulus   
    else:
        #Fancypants method for large n
        for i in range(1,modulus-n):
            ans = (ans * i) % modulus
        ans = inverse_mod(ans, modulus)

        #Since m is an odd-prime, (-1)^(m-n) = -1 if n is even, +1 if n is odd
        if n % 2 == 0:
            ans = -1*ans + modulus
    return ans % modulus

def decrypt(p):
    e = 65537
    ct = 11776079752956619284016871274992903352398310565005810097721997339193718454945819135683541554652454321040530044545154341786048659896370226535387839157317585368391189570502841702311449000698372030666509296004039398083488490698999338894328619127149024309470011330855840757405205104944658961386764569043610715311746676861275270073394069269043429092551681704290340091149637137627751767730812255069347108706434972786681985484368054390699974613090342753508097177008167140924577095976699437810398922852319420301082587264411993737330188227703869101718515748828944300463051133118636928879090217708121368293440440444106196607645
    q = n // p
    φ = (p-1) * (q-1)
    d = pow(e, -1, φ)
    print(long_to_bytes(pow(ct, d, n)))
    exit()

for delta in tqdm(range(0x1337, 0x1337 + 0x1337 + 1)):
    pp = p - delta
    ppp = prevprime(factorialMod(pp, p))
    qq = q - delta
    qqq = prevprime(factorialMod(pp, p))
    if not (n % ppp):
        decrypt(ppp)
    elif not (n % qqq):
        decrypt(qqq)

#1639/4920 
#b'vsctf{Strongest_can_be_the_weakest:(}'

```

<p> <b>Flag :</b> vsctf{Strongest_can_be_the_weakest:(} </p>

<br/>

## Baby RSA

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img4.png)

The pubkey.pem file can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2022/vsctf2022/babyRSA/pubkey.pem">here</a>. 

Source code :

```py

from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from secret import e

with open("flag.txt",'r') as f:
    flag = f.read().strip()

p = getPrime(128)
q = getPrime(128)

while p % e != 1:
    p = getPrime(128)
while q % e != 1:
    q = getPrime(128)

n = p * q
m = bytes_to_long(flag.encode())
c = pow(m, e, n)
print(f"Ciphertext: {hex(c)}")

with open("pubkey.pem",'w') as f:
    pk = RSA.construct([n, e])
    f.write(pk.exportKey('PEM').decode('utf-8'))

# Ciphertext: 0x459cc234f24a2fb115ff10e272130048d996f5b562964ee6138442a4429af847

```

Solve script :

```py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#key_encoded='''-----BEGIN PUBLIC KEY-----
#MDkwDQYJKoZIhvcNAQEBBQADKAAwJQIgc+RINge/zsBmxaAC/gP7Cc/g9t3lV1Nv
#n0fVaCXTj+8CAWU=
#-----END PUBLIC KEY-----'''

#pubkey2 = serialization.load_pem_public_key(
    #key_encoded.encode('ascii'),
    #backend=default_backend()
#)

#n = pubkey2.public_numbers().n
#e = pubkey2.public_numbers().e

n = 52419317100235286358057114349639882093779997394202082664044401328860087685103
#factor(n)
e = 101
ct = 0x459cc234f24a2fb115ff10e272130048d996f5b562964ee6138442a4429af847
p = 184980129074643957218827272858529362113
q = 283378097758180413812138939650885549231

def roots_of_unity(e, phi, n, rounds=250):
    # Divide common factors of `phi` and `e` until they're coprime.
    phi_coprime = phi
    while gcd(phi_coprime, e) != 1:
        phi_coprime //= gcd(phi_coprime, e)

    # Don't know how many roots of unity there are, so just try and collect a bunch
    roots = set(pow(i, phi_coprime, n) for i in range(1, rounds))

    assert all(pow(root, e, n) == 1 for root in roots)
    return roots, phi_coprime

# n is prime
# Problem: e and phi are not coprime - d does not exist
phi = (p - 1) * (q - 1)

# Find e'th roots of unity modulo n
roots, phi_coprime = roots_of_unity(e, phi, n)

# Use our `phi_coprime` to get one possible plaintext
d = inverse_mod(e, phi_coprime)
pt = pow(ct, d, n)
assert pow(pt, e, n) == ct

# Use the roots of unity to get all other possible plaintexts
pts = [(pt * root) % n for root in roots]
pts = [long_to_bytes(pt) for pt in pts]

for possibleFlag in pts:
    if b'vsctf{' in possibleFlag:
        print(possibleFlag)
        exit()

#b'vsctf{5m411_Pr1m3_15_Un54f3!}'

```

<p> <b>Flag :</b> vsctf{Strongest_can_be_the_weakest:(} </p>

<br/>

## Hexahue Hate

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img5.png)

The attached png can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2022/vsctf2022/hexahueHate/hexhuebad.png" target="_blank">here</a>.

Solve script :

```py

from multiprocessing.sharedctypes import Value
from PIL import Image

# init colors, to init dictionary more easily
white = (255, 255, 255)
black = (0, 0, 0)
red = (255, 0, 0)
green = (0, 255, 0)
blue = (0, 0, 255)
yellow = (255, 255, 0)
light_blue = (0, 255, 255)
magenta = (255, 0, 255)
gray = (128, 128, 128)

# init dict
# keys are tuples of tuples of the six colors, values are the decoded values
hexahue = {}
hexahue[(magenta, red, green, yellow, blue, light_blue)] = 'a'
hexahue[(red, magenta, green, yellow, blue, light_blue)] = 'b'
hexahue[(red, green, magenta, yellow, blue, light_blue)] = 'c'
hexahue[(red, green, yellow, magenta, blue, light_blue)] = 'd'
hexahue[(red, green, yellow, blue, magenta, light_blue)] = 'e'
hexahue[(red, green, yellow, blue, light_blue, magenta)] = 'f'
hexahue[(green, red, yellow, blue, light_blue, magenta)] = 'g'
hexahue[(green, yellow, red, blue, light_blue, magenta)] = 'h'
hexahue[(green, yellow, blue, red, light_blue, magenta)] = 'i'
hexahue[(green, yellow, blue, light_blue, red, magenta)] = 'j'
hexahue[(green, yellow, blue, light_blue, magenta, red)] = 'k'
hexahue[(yellow, green, blue, light_blue, magenta, red)] = 'l'
hexahue[(yellow, blue, green, light_blue, magenta, red)] = 'm'
hexahue[(yellow, blue, light_blue, green, magenta, red)] = 'n'
hexahue[(yellow, blue, light_blue, magenta, green, red)] = 'o'
hexahue[(yellow, blue, light_blue, magenta, red, green)] = 'p'
hexahue[(blue, yellow, light_blue, magenta, red, green)] = 'q'
hexahue[(blue, light_blue, yellow, magenta, red, green)] = 'r'
hexahue[(blue, light_blue, magenta, yellow, red, green)] = 's'
hexahue[(blue, light_blue, magenta, red, yellow, green)] = 't'
hexahue[(blue, light_blue, magenta, red, green, yellow)] = 'u'
hexahue[(light_blue, blue, magenta, red, green, yellow)] = 'v'
hexahue[(light_blue, magenta, blue, red, green, yellow)] = 'w'
hexahue[(light_blue, magenta, red, blue, green, yellow)] = 'x'
hexahue[(light_blue, magenta, red, green, blue, yellow)] = 'y'
hexahue[(light_blue, magenta, red, green, yellow, blue)] = 'z'
hexahue[(black, white, white, black, black, white)] = '.'
hexahue[(white, black, black, white, white, black)] = ','
hexahue[(white, white, white, white, white, white)] = ' '
hexahue[(black, black, black, black, black, black)] = ' '
hexahue[(black, gray, white, black, gray, white)] = '0'
hexahue[(gray, black, white, black, gray, white)] = '1'
hexahue[(gray, white, black, black, gray, white)] = '2'
hexahue[(gray, white, black, gray, black, white)] = '3'
hexahue[(gray, white, black, gray, white, black)] = '4'
hexahue[(white, gray, black, gray, white, black)] = '5'
hexahue[(white, black, gray, gray, white, black)] = '6'
hexahue[(white, black, gray, white, gray, black)] = '7'
hexahue[(white, black, gray, white, black, gray)] = '8'
hexahue[(black, white, gray, white, black, gray)] = '9'

im = Image.open("hexhuebad.png")
w, h = im.size
ds = ""

x = 11
LETTER_WIDTH = 21

while (x < w):

    b1, b2 = im.getpixel((x, 11)), im.getpixel((x + 10, 11))
    b3, b4 = im.getpixel((x, 21)), im.getpixel((x + 10, 21))
    b5, b6 = im.getpixel((x, 31)), im.getpixel((x + 10, 31))

    current_letter = (b1, b2, b3, b4, b5, b6)
    ds += hexahue[current_letter]

    whiteBufferX = x + LETTER_WIDTH

    try:
        while (im.getpixel((whiteBufferX, 11)) == white):
            whiteBufferX += 1
    except IndexError:
        break
        
    if 60 > (whiteBufferX - x - LETTER_WIDTH) > 30:
        ds += " "
    elif (whiteBufferX - x - LETTER_WIDTH) > 60:
        ds += ", "

    x = whiteBufferX + 1

print(f"{ds=}")

#vsctf{IHATEHEXAHUESOMUCHPLEASEHELP}

```

<p> <b>Flag :</b> vsctf{IHATEHEXAHUESOMUCHPLEASEHELP} </p>

<br/>

## Recovery

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img6.png)

Source code :

```py

# I coded this so that I wouldn't have to use a database!
from random import randint
from base64 import b64encode


def validate(password: str) -> bool:
    if len(password) != 49:
        return False

    key = ['vs'.join(str(randint(7, 9)) for _ in range(ord(i))) + 'vs' for i in password[::-2]]
    gate = [118, 140, 231, 176, 205, 480, 308, 872, 702, 820, 1034, 1176, 1339, 1232, 1605, 1792, 782, 810, 1197, 880,
            924, 1694, 2185, 2208, 2775]
    if [randint(a, b[0]) for a, b in enumerate(zip(gate, key), 1) if len(b[1]) != 3 * (b[0] + 7 * a) // a]:
        return False

    hammer = {str(a): password[a] + password[a + len(password) // 2] for a in range(1, len(password) // 2, 2)}
    block = b'c3MxLnRkMy57XzUuaE83LjVfOS5faDExLkxfMTMuR0gxNS5fTDE3LjNfMTkuMzEyMS5pMzIz'
    if b64encode(b'.'.join([((b + a).encode()) for a, b in hammer.items()])) != block:
        return False

    return True


if __name__ == "__main__":
    passwd = input('Please validate your ID using your password\n> ')
    if validate(passwd):
        print('Access Granted: You now have gained access to the View Source Flag Vault!')
    else:
        print('Access Denied :(')
        
```

Solve script :

```py

from random import randint
import base64

base64_message = 'c3MxLnRkMy57XzUuaE83LjVfOS5faDExLkxfMTMuR0gxNS5fTDE3LjNfMTkuMzEyMS5pMzIz=='
base64_bytes = base64_message.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)
message = message_bytes.decode('ascii')
decodeB64 = 'ss1.td3.{_5.hO7.5_9._h11.L_13.GH15._L17.3_19.3121.i323'

ts = decodeB64.split(".")
ts = [(i[:2], i[2:]) for i in ts]

realPassword = ["_"] * 49

for i in (ts):
    realPassword[int(i[1])] = i[0][0]
    realPassword[int(i[1]) + 49 // 2 ] = i[0][1]

gate = [118, 140, 231, 176, 205, 480, 308, 872, 702, 820, 1034, 1176, 1339, 1232, 1605, 1792, 782, 810, 1197, 880, 924, 1694, 2185, 2208, 2775]
a = 1

for i in range(0, 49, 2):
    const = 3 * (gate[i//2] + 7 * a) // a
    realPassword[48-i] = chr(const//3)
    a += 1

print(''.join(realPassword))

#vsctf{Th353_FL4G5_w3r3_inside_YOU_th3_WH0L3_T1M3}

```

<p> <b>Flag :</b> vsctf{Th353_FL4G5_w3r3_inside_YOU_th3_WH0L3_T1M3} </p>

<br/>

## Discord

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img7.png)

<p> <b>Flag :</b> vsctf{w3lc0m3_t0_vsctf_2022!} </p>

<br/>

## Feedback Survey

![vsCTF 2022 Writeup](/assets/img/ctfImages/2022/vsctf2022/img8.png)

<p> <b>Flag :</b> vsctf{surv3y_c0mpl3t3r} </p>

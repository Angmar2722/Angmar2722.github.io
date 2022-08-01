---
layout: page
title: Random CTF Solves (2022) 
---
<hr/>

![Random 2021 Writeup](/assets/img/ctfImages/2021/randomCTFs2021/img18.png)

Due to a lack of time or due to playing another CTF which was occuring at the same time, I couldn't really spend much time at all for some CTFs. Below is the directory for some solve scripts for random cryptography challenges that I solved during the duration of such CTFs :

Below are the writeups :

| Challenge | CTF | Weight | Solves | 
| ------------- |  ------- | --- | ---: |
|[Elliptic Clock Crypto](#elliptic-clock-crypto) | <a href="https://ctftime.org/event/1600" target="_blank">UIUCTF 2022</a> | 34.64 | 27/395 | 
|[Asr](#asr) | <a href="https://ctftime.org/event/1600" target="_blank">UIUCTF 2022</a> | 34.64 | 56/395 | 
|[Reverse RSA](#reverse-rsa) | <a href="https://ctftime.org/event/1706" target="_blank">DiceCTF @HOPE 2022</a> | 47.77 | 39/410 | 
|[Replacement](#replacement) | <a href="https://ctftime.org/event/1706" target="_blank">DiceCTF @HOPE 2022</a> | 47.77 | 55/410 | 
|[DESpicable You](#despicable-you) | <a href="https://ctftime.org/event/1706" target="_blank">DiceCTF @HOPE 2022</a> | 47.77 | 61/410 | 
|[Kfb](#kfb) | <a href="https://ctftime.org/event/1706" target="_blank">DiceCTF @HOPE 2022</a> | 47.77 | 95/410 | 
|[Pem](#pem) | <a href="https://ctftime.org/event/1706" target="_blank">DiceCTF @HOPE 2022</a> | 47.77 | 150/410 | 
|[Obp](#obp) | <a href="https://ctftime.org/event/1706" target="_blank">DiceCTF @HOPE 2022</a> | 47.77 | 207/410 | 

<br/>

<br/>

## UIUCTF 2022

![Random 2022 Writeup](/assets/img/ctfImages/2022/uiuctf2022/uiuctflogo.png)

Spent a bit of time on the challenge `That-crete log` but was unable to solve it. Neobeo solved it in the end.

<br/>

## Elliptic Clock Crypto

![Random 2022 Writeup](/assets/img/ctfImages/2022/uiuctf2022/uiuctfimg1.png)

The attached output file can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/blob/master/assets/ctfFiles/2022/uiuctf2022/ellipticClockCrypto/output.txt" target="_blank">here</a>.

Source code :

```py

# Code inspired by https://ecchacks.cr.yp.to/clockcrypto.py

from random import seed, randrange
from hashlib import md5
from Crypto.Cipher import AES

from secret import FLAG

# 256-bit security!
p = 62471552838526783778491264313097878073079117790686615043492079411583156507853

class Fp:
    def __init__(self,x):
        self.int = x % p
    def __str__(self):
        return str(self.int)
    __repr__ = __str__
    def __int__(self):
        return self.int
    def __eq__(a,b):
        return a.int == b.int
    def __ne__(a,b):
        return a.int != b.int
    def __add__(a,b):
        return Fp(a.int + b.int)
    def __sub__(a,b):
        return Fp(a.int - b.int)
    def __mul__(a,b):
        return Fp(a.int * b.int)
    def __truediv__(a,b):
        return a*Fp(pow(b.int,-1,p))

class ClockPoint:
    def __init__(self,x,y):
        assert int(x*x + y*y) == 1
        self.x = x
        self.y = y
    def __str__(self):
        return f"({self.x},{self.y})"
    def __eq__(self, other):
        return str(self) == str(other)
    __repr__ = __str__
    def get_hash(self):
        return md5(str(self).encode()).digest()
    def __add__(self, other):
        x1,y1 = self.x, self.y
        x2,y2 = other.x, other.y
        return ClockPoint( x1*y2+y1*x2, y1*y2-x1*x2 )

def scalar_mult(x: ClockPoint, n: int) -> ClockPoint:
    y = ClockPoint(Fp(0),Fp(1))
    if n == 0: return y
    if n == 1: return x
    while n > 1:
        if n % 2 == 0:
            x = x + x
            n = n // 2
        else:
            y = x + y
            x = x + x
            n = (n-1) // 2
    return x + y


base_point = ClockPoint(Fp(34510208759284660042264570994647050969649037508662054358547659196695638877343),Fp(4603880836195915415499609181813839155074976164846557299963454168096659979337))

alice_secret = randrange(2**256)
alice_public = scalar_mult(base_point, alice_secret)
print("Alice's public key: ", alice_public)
bob_secret = randrange(2**256)
bob_public = scalar_mult(base_point, bob_secret)
print("Bob's public key: ", bob_public)

assert scalar_mult(bob_public, alice_secret) == scalar_mult(alice_public, bob_secret)
shared_secret = scalar_mult(bob_public, alice_secret)
key = shared_secret.get_hash()

print("Encrypted flag: ", AES.new(key, AES.MODE_ECB).encrypt(FLAG))

```

Solve script :

```py

from sage.all import *
from random import seed, randrange
from hashlib import md5
from Crypto.Cipher import AES

p = 62471552838526783778491264313097878073079117790686615043492079411583156507853
A_pk = (929134947869102207395031929764558470992898835457519444223855594752208888786,6062966687214232450679564356947266828438789510002221469043877962705671155351)
B_pk = (49232075403052702050387790782794967611571247026847692455242150234019745608330,46585435492967888378295263037933777203199027198295712697342810710712585850566)
G = (34510208759284660042264570994647050969649037508662054358547659196695638877343, 4603880836195915415499609181813839155074976164846557299963454168096659979337)

def phi(x, y, p):
    a = Mod(-1, p).sqrt()
    x, y = x, y
    return x - a*y

A_u = Mod(phi(A_pk[0], A_pk[1], p), p)
G_u = Mod(phi(G[0], G[1], p), p)

A_sk = A_u.log(G_u)
print(f"{A_sk=}")

B_u = Mod(phi(B_pk[0], B_pk[1], p), p)
G_u = Mod(phi(G[0], G[1], p), p)

B_sk = B_u.log(G_u)
print(f"{B_sk=}")

class Fp:
    def __init__(self,x):
        self.int = x % p
    def __str__(self):
        return str(self.int)
    __repr__ = __str__
    def __int__(self):
        return self.int
    def __eq__(a,b):
        return a.int == b.int
    def __ne__(a,b):
        return a.int != b.int
    def __add__(a,b):
        return Fp(a.int + b.int)
    def __sub__(a,b):
        return Fp(a.int - b.int)
    def __mul__(a,b):
        return Fp(a.int * b.int)
    def __truediv__(a,b):
        return a*Fp(pow(b.int,-1,p))

class ClockPoint:
    def __init__(self,x,y):
        assert int(x*x + y*y) == 1
        self.x = x
        self.y = y
    def __str__(self):
        return f"({self.x},{self.y})"
    def __eq__(self, other):
        return str(self) == str(other)
    __repr__ = __str__
    def get_hash(self):
        return md5(str(self).encode()).digest()
    def __add__(self, other):
        x1,y1 = self.x, self.y
        x2,y2 = other.x, other.y
        return ClockPoint( x1*y2+y1*x2, y1*y2-x1*x2 )

def scalar_mult(x: ClockPoint, n: int) -> ClockPoint:
    y = ClockPoint(Fp(0),Fp(1))
    if n == 0: return y
    if n == 1: return x
    while n > 1:
        if n % 2 == 0:
            x = x + x
            n = n // 2
        else:
            y = x + y
            x = x + x
            n = (n-1) // 2
    return x + y

base_point = ClockPoint(Fp(34510208759284660042264570994647050969649037508662054358547659196695638877343),Fp(4603880836195915415499609181813839155074976164846557299963454168096659979337))
B_pk = ClockPoint(Fp(49232075403052702050387790782794967611571247026847692455242150234019745608330),Fp(46585435492967888378295263037933777203199027198295712697342810710712585850566))
bob_public = scalar_mult(base_point, B_sk)
shared_secret = scalar_mult(bob_public, A_sk)
key = shared_secret.get_hash()

ct = b' \xe9\x1aY.+E\xac\x1b\xc41\x1c\xf7\xba}\x80\x11\xa8;%]\x93\x88\x1fu\x87\x91\x88\x87\x88\x9b\x19'
print(AES.new(key, AES.MODE_ECB).decrypt(ct))
#b'uiuctf{Circle5_ar3_n0t_ell1ptic}'

```

<p> <b>Flag :</b> uiuctf{Circle5_ar3_n0t_ell1ptic} </p>

<br/>

## Asr

![Random 2022 Writeup](/assets/img/ctfImages/2022/uiuctf2022/uiuctfimg2.png)

Source code :

```py

from secret import flag
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from math import prod

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
def gen_prime(bits, lim = 7, sz = 64):
    while True:
        p = prod([getPrime(sz) for _ in range(bits//sz)])
        for i in range(lim):
            if isPrime(p+1):
                return p+1
            p *= small_primes[i]

p = gen_prime(512)
q = gen_prime(512)
n = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = pow(e, -1, phi)

msg = bytes_to_long(flag)
ct = pow(msg, e, n)

print("e = ", e)
print("d = ", d)
print("ct = ", ct)
'''
e = 65537
d = 195285722677343056731308789302965842898515630705905989253864700147610471486140197351850817673117692460241696816114531352324651403853171392804745693538688912545296861525940847905313261324431856121426611991563634798757309882637947424059539232910352573618475579466190912888605860293465441434324139634261315613929473
ct = 212118183964533878687650903337696329626088379125296944148034924018434446792800531043981892206180946802424273758169180391641372690881250694674772100520951338387690486150086059888545223362117314871848416041394861399201900469160864641377209190150270559789319354306267000948644929585048244599181272990506465820030285
'''

```

Solve script :

```py

from Crypto.Util.number import *
from tqdm import tqdm

e = 65537
d = 195285722677343056731308789302965842898515630705905989253864700147610471486140197351850817673117692460241696816114531352324651403853171392804745693538688912545296861525940847905313261324431856121426611991563634798757309882637947424059539232910352573618475579466190912888605860293465441434324139634261315613929473
ct = 212118183964533878687650903337696329626088379125296944148034924018434446792800531043981892206180946802424273758169180391641372690881250694674772100520951338387690486150086059888545223362117314871848416041394861399201900469160864641377209190150270559789319354306267000948644929585048244599181272990506465820030285

ks = []

#ed = 1 + k(p-1)(q-1)
#k bit length is about e
for k in range(2, 65537):
	if (e * d - 1) % k == 0 and ((e * d - 1) // k).bit_length() <= 1035:
		ks.append(k)

#print(f"List of possible Ks = {ks}")
possiblePhis = []

for k in tqdm(ks):
    phi = (e*d - 1) // k
    if (phi % 4) != 0 or (phi % 9) != 0 or (phi % 5) != 0 or (phi % 7) != 0 or (phi % 11) != 0:
        continue
    possiblePhis.append(phi)

print(f"{possiblePhis=}")

#phi1 = 357099341716100220675217190975124789231027312767102701387570615334094516456115237551569392796961892041486051457525056954165755553971129842919771722026926765108290190117901376929980893064154312350165621375309875385216456969264597107438337687144134392221931753668408310769546938226920888261197018393152450931643300
#factors = 2^2 · 3^3 · 5^2 · 7 · 11 · 13923226921736843531<20> · 15789155524315171763<20> · 7813322605...59<268>

#phi2 =333292718935026872630202711576783136615625491915962521295065907645154882025707555048131433277164432572053648027023386490554705183706387853391786940558464980767737510776707951801315500193210691526821246616955883692868693171313623966942448508001192099407136303423847756718243809011792829043783883833608954202867080
#factors = 2^3 · 3^2 · 5 · 7^2 · 11 · 13923226921736843531<20> · 15789155524315171763<20> · 7813322605...59<268>

#phi3 =285679473372880176540173752780099831384821850213682161110056492267275613164892190041255514237569513633188841166020045563332604443176903874335817377621541412086632152094321101543984714451323449880132497100247900308173165575411677685950670149715307513777545402934726648615637550581536710608957614714521960745314640
#factors = 2^4 · 3^3 · 5 · 7 · 11 · 13923226921736843531<20> · 15789155524315171763<20> · 7813322605...59<268>

#phi4 = 238066227810733480450144793983416526154018208511401800925047076889396344304076825034379595197974594694324034305016704636110503702647419895279847814684617843405526793411934251286653928709436208233443747583539916923477637979509731404958891791429422928147954502445605540513031292151280592174131345595434967287762200
#factors = 2^3 · 3^2 · 5^2 · 7 · 11 · 13923226921736843531<20> · 15789155524315171763<20> · 7813322605...59<268>

'''
sage: factor(3570993417161002206752171909751247892310273127671027013875706153340945164561152375515693927969618920414860
....: 51457525056954165755553971129842919771722026926765108290190117901376929980893064154312350165621375309875385216456
....: 969264597107438337687144134392221931753668408310769546938226920888261197018393152450931643300)
2^2 * 3^3 * 5^2 * 7 * 11 * 10357495682248249393 * 10441209995968076929 * 10476183267045952117 * 11157595634841645959 * 11865228112172030291 * 12775011866496218557 * 13403263815706423849 * 13923226921736843531 * 14497899396819662177 * 14695627525823270231 * 15789155524315171763 * 16070004423296465647 * 16303174734043925501 * 16755840154173074063 * 17757525673663327889 * 18318015934220252801
'''

from math import prod
from itertools import combinations

inall = [10357495682248249393, 10441209995968076929, 10476183267045952117, 11157595634841645959, 11865228112172030291, 12775011866496218557, 13403263815706423849, 13923226921736843531, 14497899396819662177, 14695627525823270231, 15789155524315171763, 16070004423296465647, 16303174734043925501, 16755840154173074063, 17757525673663327889, 18318015934220252801]

tl = [i for i in combinations(inall, 8)]
ns = []

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

def gen_prime(tl, lim = 7):
    p = prod(tl)
    for i in range(lim):
        if isPrime(p+1):
            return p+1
        p *= small_primes[i]

possiblePrimes = []

for ok in tqdm(tl):
    t = gen_prime(ok)
    if t is not None:
        possiblePrimes.append(t)

ns = [(i[0], i[1]) for i in combinations(possiblePrimes, 2) if pow(e, -1, (i[0]-1)*(i[1]-1)) == d]

for n in tqdm(ns):
    flag = long_to_bytes(pow(ct, d, prod(n)))
    if b'uiuctf{' in flag:
        print(flag)
        exit()

#b'uiuctf{bru4e_f0rc3_1s_FUn_fuN_Fun_f0r_The_whOLe_F4miLY!}'

```

<p> <b>Flag :</b> uiuctf{bru4e_f0rc3_1s_FUn_fuN_Fun_f0r_The_whOLe_F4miLY!} </p>

<br/>

<br/>

## DiceCTF @Hope 2022

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img1.png)

All of the attached output files can be found <a href="https://github.com/Angmar2722/Angmar2722.github.io/tree/master/assets/ctfFiles/2022/diceHope2022/crypto" target="_blank">here</a>.

<br/>

## Reverse RSA

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img2.png)

Source code :

```py

#!/usr/local/bin/python

import re
from Crypto.Util.number import isPrime, GCD

flag_regex = rb"hope{[a-zA-Z0-9_\-]+}"

with open("ciphertext.txt", "r") as f:
	c = int(f.read(), 10)

print(f"Welcome to reverse RSA! The encrypted flag is {c}.  Please provide the private key.")

p = int(input("p: "), 10)
q = int(input("q: "), 10)
e = int(input("e: "), 10)

N = p * q
phi = (p-1) * (q-1)

if (p < 3) or not isPrime(p) or (q < 3) or not isPrime(q) or (e < 2) or (e > phi) or GCD(p,q) > 1 or GCD(e, phi) != 1:
	print("Invalid private key")
	exit()


d = pow(e, -1, phi)
m = pow(c, d, N)

m = int.to_bytes(m, 256, 'little')
m = m.strip(b"\x00")

if re.fullmatch(flag_regex, m) is not None:
	print("Clearly, you must already know the flag!")

	with open('flag.txt','rb') as f:
		flag = f.read()
		print(flag.decode())

else:
	print("hack harder")

```

Solve script :

```py

from pwn import *
from Crypto.Util.number import *
import random
from tqdm import tqdm

allowed = string.ascii_letters + string.digits

#}......{epoh
def getFormat():
    return "}" + ''.join([random.choice(allowed) for i in range((250))]) + "{epoh"

p,q = 2^188 * 5^360+1, 2 * 11^45 * 17^212+1
c = 7146993245951509380139759140890681816862856635262037632915667109712467317954902955151177421740994622238561522690931235839733579166121631742096762557444153806131985279962646477997889661633938981817306610901055296705982494607773446985300816341071922739788638126631520234249358834592814880445497817389957300553660499631838091201561728727996660871094966330045071879490277901216751327226984526095495604592577841120425249633624459211547984305731778854596177467026282357094690700361174790351699376317810120824316300666128090632100150965101285647544696152528364989155735157261219949095760495520390692941417167332814540685297
N = p*q

def get_e(s):
    sp = GF(p)(s)
    sq = GF(q)(s)
    dp = sp.log(c)
    dq = sq.log(c)
    d = crt([dp, dq], [p-1, q-1])
    return pow(int(d), -1, lcm(p-1, q-1)).lift(), d

for i in tqdm(range(1000)):

    try:

        toPass = bytes_to_long(getFormat().encode())
        assert toPass < N

        e, d = get_e(toPass)
        assert pow(c, d, N) == toPass
        break

    except ValueError:
        continue
    except AssertionError:
        continue
    except ZeroDivisionError:
        continue

print(f"{e=}")
print(f"{d=}")
print(f"{toPass=}")

debug = False
r = remote("mc.ax", 31669, level = 'debug' if debug else None)

r.sendlineafter('p: ', str(p))
r.sendlineafter('q: ', str(q))
r.sendlineafter('e: ', str(e))
print(r.recvall())
#b'Clearly, you must already know the flag!\nhope{successful_decryption_doesnt_mean_correct_decryption_0363f29466b883edd763dc311716194d37dff5cd93cd4f1b4ac46152f4f9}\n'

```

<p> <b>Flag :</b> hope{successful_decryption_doesnt_mean_correct_decryption_0363f29466b883edd763dc311716194d37dff5cd93cd4f1b4ac46152f4f9} </p>

<br/>

## Replacement

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img3.png)

Source code :

```py

import random

with open('text.txt') as f:
    plaintext = f.read()

with open('flag.txt') as f:
    plaintext += '\n' + f.read()

characters = set(plaintext) - {'\n'}

shuffled = list(characters)
random.shuffle(shuffled)

replacement = dict(zip(characters, shuffled))

ciphertext = ''.join(replacement.get(c, c) for c in plaintext)

with open('output.txt', 'w') as f:
    f.write(ciphertext)

```

Solve script :

```py

import collections

f = open('output.txt')
ctl = f.readlines()
f.close()
#print(ctl)

print("-"*100)

s = ''.join(ctl)
#print(set(s))
#{'v', 'i', 'j', 'e', 'y', 'w', 'l', ' ', 'a', 'A', 'g', '.', '{', 'T', 't', 'q', 'm', 'p', 'B', 'c', 'f', 'd', 'o', 'h', 'V', '\n', 'I', '_', 'E', 'x', '}', 'O', 'n', 'S', 'u', 'k', 's', 'r', ',', 'b', '"', 'M'}
print(collections.Counter(s).most_common(42))

print("-"*100)

#Started with :
replacement = {"h" : "h", "o" : "w", "p" : "f", "e" : "y", "{" : "A", "}" : "u", "\n" : "\n"}

#Ended with (Trial and error) :
replacement = {"h" : "h", "o" : "w", "p" : "f", "e" : "y", "{" : "A", "}" : "u", "\n" : "\n", 'a' : '"', "n" : "S", "d" : "d", "t" : "k", "u" : "l", "c" : "s", "l" : "i", "i" : "q", "r" : ".", "m" : "}", "g" : "M", "s" : "_", "f" : "c", "y" : "t", "b" : "j", "v" : "V", "x" : ",", "w" : " ", "q" : "e", "A" : "o", "B" : "a", "M" : "v", " " : "g", "." : "B", "T" : "{", "k" : "E", "," : "r", "O" : "p", "V" : "O", "_" : "T", '"' : "b", "S" : "m", "I" : "x", "E" : "n", "j" : "I"}

fs = [" "*len(ct) for ct in ctl]

def getKeyFromVal(d, ts):
    key_list = list(d.keys())
    val_list = list(d.values())
    position = val_list.index(ts)
    return key_list[position]

val_list = list(replacement.values())

for i in range(len(ctl)):
    #print(f"{ctl[i]=}")
    cps = list(ctl[i])
    fss = list(fs[i])

    for j in range(len(ctl[i])):
        if ctl[i][j] in val_list:
            cps[j] = getKeyFromVal(replacement, ctl[i][j])
            fss[j] = cps[j]

    ctl[i] = ''.join(cps)
    fs[i] = ''.join(fss)
    #print(f"{ctl[i]}")

for f in fs:
    print(f)

print("-"*100)

#hope{not_the_greatest_switcheroo_ibpsnxybkenalxmfndjffds}

```

<p> <b>Flag :</b> hope{not_the_greatest_switcheroo_ibpsnxybkenalxmfndjffds} </p>

<br/>

## DESpicable You

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img4.png)

Source script :

```py

from os import urandom

def encipher(a,b):
    c = ''
    for i, j in zip(a,b):
        c+=chr(ord(i)^ord(j))
    return c

def rekey(key):
    k = ""
    for i,c in enumerate(key):
        if i == len(key)-1:
            k += c
            k += chr(ord(c)^ord(key[0]))
        else:
            k += c
            k += chr(ord(c)^ord(key[i+1]))
    key = k

def main():
    key = urandom(8)

    with open('flag.txt') as f:
        plaintext = f.read()

    i = 0
    ct = ''
    while i < len(plaintext):
        ct += encipher(plaintext[i:i+len(key)],key)
        i += len(key)
        rekey(key)
    f2 = open('output.txt', 'w')
    f2.write(ct)
    f2.close()

main()

```

Solve script :

```py

from tqdm import tqdm
from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
import re

f = open('output.txt', 'rb')
ct = f.read()
print(f"{ct=}")

f5 = b'hope{'
k5 = strxor(f5, ct[:5])

def encipher(a,b):
    c = b''
    for i, j in zip(a,b):
        c += long_to_bytes(i^j)
    return c

def isASCII(s):
    return all(32 <= b <= 126 for b in s)

def checkKey(key, ct):

    check = strxor(key, ct[:8])
    if not isASCII(check): return None

    i = 0
    pt = b''
    while i < len(ct):
        pt += encipher(ct[i:i+len(key)],key)
        i += len(key)

    flag_regex = rb"hope{[a-zA-Z0-9_\-]+}"
    if re.fullmatch(flag_regex, pt[:-1]) is not None:
        return pt

    return None

combs = [long_to_bytes(i) for i in range(65536, 256**3)]
print(f"Finished Generated Combs")

for comb in tqdm(combs):
    key = k5 + comb
    if checkKey(key, ct):
        print(f"Possible Flag : {checkKey(key, ct)}")

#Possible Flag : b'hope{maybe_1_sh0ulD_h4v3_h1R3d_4_5p3c1471st_5tgkjs3bgRh}\n'

```

<p> <b>Flag :</b> hope{maybe_1_sh0ulD_h4v3_h1R3d_4_5p3c1471st_5tgkjs3bgRh} </p>

<br/>

## Kfb

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img5.png)

```py

#!/usr/local/bin/python -u

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
from more_itertools import ichunked

BLOCK = AES.block_size
FLAG = open('flag.txt', 'rb').read().strip()

def encrypt_block(k, pt):
  cipher = AES.new(k, AES.MODE_ECB)
  return cipher.encrypt(pt)

def encrypt(k, pt):
  assert len(k) == BLOCK
  pt = pad(pt, BLOCK)
  ct = b''
  for bk in ichunked(pt, BLOCK):
    ct += strxor(encrypt_block(k, k), bytes(bk))
  return ct

def main():
  k = get_random_bytes(BLOCK)
  enc = encrypt(k, FLAG)
  print(f'> {enc.hex()}')

  pt = bytes.fromhex(input('< '))[:BLOCK]
  enc = encrypt(k, pt)
  print(f'> {enc.hex()}')

if __name__ == '__main__':
  main()

```

Solve script :

```py

from pwn import *
from Crypto.Util.number import bytes_to_long
from more_itertools import ichunked
from Crypto.Util.strxor import strxor

debug = True
r = remote("mc.ax", 31968, level = 'debug' if debug else None)

r.recvuntil('> ')
ct = r.recvline(keepends=False).decode()
print(f"{ct=}")

ts = hex(bytes_to_long(b'0'*16))[2:]
r.sendline(ts)
ct2 = r.recvline(keepends=False)[4:].decode()
print(f"{ct2=}")

ct, ct2 = bytes.fromhex(ct), bytes.fromhex(ct2)
encKey = strxor(ct2[:16], b'0'*16)

flag = b''

for bk in ichunked(ct, 16):
    flag += strxor(encKey, bytes(bk))

print(flag)
#b'hope{kfb_should_stick_to_stuff_he_knows_b3358db7e883ed54}\x07\x07\x07\x07\x07\x07\x07'

```

<p> <b>Flag :</b> hope{kfb_should_stick_to_stuff_he_knows_b3358db7e883ed54} </p>

<br/>

## Pem

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img6.png)

Source code :

```py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

with open('flag.txt','rb') as f:
	flag = f.read()

key = RSA.generate(2048)
cipher_rsa = PKCS1_OAEP.new(key)
enc = cipher_rsa.encrypt(flag)

with open('privatekey.pem','wb') as f:
	f.write(key.export_key('PEM'))

with open("encrypted.bin", "wb") as f:
	f.write(enc)

```

Solve script :

```py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

f = open("encrypted.bin","rb")
ct = f.read()
f.close()

key = RSA.importKey(open('privatekey.pem').read())
cipher_rsa = PKCS1_OAEP.new(key)
print(cipher_rsa.decrypt(ct))
#b'hope{crypto_more_like_rtfm_f280d8e}'

```

<p> <b>Flag :</b> hope{crypto_more_like_rtfm_f280d8e} </p>

<br/>

## Obp

![Random 2022 Writeup](/assets/img/ctfImages/2022/diceHope2022/img7.png)

Source code :

```py

import random

with open('flag.txt', 'rb') as f:
    plaintext = f.read()

key = random.randrange(256)
ciphertext = [key ^ byte for byte in plaintext]

with open('output.txt', 'w') as f:
    f.write(bytes(ciphertext).hex())

```

Solve script :

```py

from tqdm import tqdm
from Crypto.Util.number import *

ct = bytes.fromhex('babda2b7a9bcbda68db38dbebda68dbdb48db9b7aba18dbfb6a2aaa7a3beb1a2bfb7b5a3a7afd8')

for key in tqdm(range(256)):
    pt = ''.join([chr(key ^ byte) for byte in ct])
    if 'hope' in pt:
        print(pt)
        exit()

#hope{not_a_lot_of_keys_mdpxuqlcpmegqu}

```

<p> <b>Flag :</b> hope{not_a_lot_of_keys_mdpxuqlcpmegqu} </p>

<br/>

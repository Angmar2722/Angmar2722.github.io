from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from collections import namedtuple
import random, sys, os, signal, hashlib
from pwn import *

local = False
debug = False

if local:
    r = process(["python3", "invincible.py"], level='debug') if debug else process(["python3", "invincible.py"])
else:
    r = remote("52.149.135.130", 4874, level = 'debug') if debug else remote("52.149.135.130", 4874)

#==================Server Code==================
Point = namedtuple("Point","x y")

class EllipticCurve:
    INF = Point(0, 0)

    def __init__(self, a, b, Gx, Gy, p):
        self.a = a
        self.b = b
        self.p = p
        self.G = Point(Gx, Gy)

    def add(self, P, Q):
        if P == self.INF:
            return Q
        elif Q == self.INF:
            return P

        if P.x == Q.x and P.y == (-Q.y % self.p):
            return self.INF
        if P != Q:
            tmp = (Q.y - P.y)*inverse(Q.x - P.x, self.p) % self.p
        else:
            tmp = (3*P.x**2 + self.a)*inverse(2*P.y, self.p) % self.p
        Rx = (tmp**2 - P.x - Q.x) % self.p
        Ry = (tmp * (P.x - Rx) - P.y) % self.p
        return Point(Rx, Ry)
        
    def multiply(self, P, n):
        R = self.INF
        while 0 < n:
            if n & 1 == 1:
                R = self.add(R, P)
            n, P = n >> 1, self.add(P, P)
        return R

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -0x3
Gx = 0x55b40a88dcabe88a40d62311c6b300e0ad4422e84de36f504b325b90c295ec1a
Gy = 0xf8efced5f6e6db8b59106fecc3d16ab5011c2f42b4f8100c77073d47a87299d8
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(a, b, Gx, Gy, p)

class RNG:
    def __init__(self, seed, P, Q):
        self.seed = seed
        self.P = P
        self.Q = Q

    def next(self):
        s = E.multiply(self.P, self.seed).x
        self.seed = s
        r = E.multiply(self.Q, s).x
        return r & ((1<<128) - 1)

def encrypt(msg, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher = aes.encrypt(msg)
    return iv + cipher

def decrypt(cipher, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    msg = aes.decrypt(cipher)
    return msg

#==================Solve Script==================

SVALS = [46111711714004764615393195350570532019484583409650937480110926637425134418118,
            82794344854243450371984501721340198645022926339504713863786955730156937886079,
            0]

Px = 82794344854243450371984501721340198645022926339504713863786955730156937886079
Py = 33552521881581467670836617859178523407344471948513881718969729275859461829010
P = Point(Px, Py)

# Our point
def sendP():
    r.sendlineafter(b"Point x : ", str(Px).encode())
    r.sendlineafter(b"Point y : ", str(Py).encode())
    r.recvline()
sendP()

# Their point
def getQ():
    r.recvuntil(b"(")
    Qx, Qy = [int(n.decode()) for n in r.recvline(keepends=False)[:-1].split(b", ")]
    Q = Point(Qx, Qy)
    return Q
Q = getQ()

keyvals = [hashlib.sha1(str(E.multiply(Q, s).x & ((1<<128) - 1)).encode()).digest()[:16] for s in SVALS]

for i in range(10):
    try:
        key = keyvals[i % len(SVALS)]
        for i in range(100):
            r.recvuntil(b" : ")
            cipher = bytes.fromhex(r.recvline(keepends=False).decode())
            iv, ct = cipher[:16], cipher[16:]
            msg = decrypt(ct, key, iv)
            r.sendlineafter(b"What was the message ? : ", msg.hex().encode())
            print(r.recvline())
        print(r.recvline())
        exit(0)

    except EOFError:
        if local:
            r = process(["python3", "invincible.py"], level='debug') if debug else process(["python3", "invincible.py"])
        else:
            r = remote("52.149.135.130", 4874, level = 'debug') if debug else remote("52.149.135.130", 4874)
        sendP()
        Q = getQ()
        keyvals = [hashlib.sha1(str(E.multiply(Q, s).x & ((1<<128) - 1)).encode()).digest()[:16] for s in SVALS]
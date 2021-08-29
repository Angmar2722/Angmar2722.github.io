from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from collections import namedtuple
import random, sys, os, signal, hashlib

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

commonS1 = 46111711714004764615393195350570532019484583409650937480110926637425134418118
commonS2 = 82794344854243450371984501721340198645022926339504713863786955730156937886079

class RNG:
    def __init__(self, seed, P, Q):
        self.seed = seed
        self.P = P
        self.Q = Q

    def next(self):
        s = E.multiply(self.P, self.seed).x
        self.seed = s
        #if (s != commonS1 and s != commonS2):
            #print(s)
        print(f"s = {s}")
        r = E.multiply(self.Q, s).x
        return r & ((1<<128) - 1)

Px = 82794344854243450371984501721340198645022926339504713863786955730156937886079
Py = 33552521881581467670836617859178523407344471948513881718969729275859461829010
P = Point(Px, Py)

for i in range(100):
    Q = E.multiply(E.G, random.randrange(1, p-1))
    rng = RNG(random.getrandbits(128), P, Q)
    for j in range(100):
        rng.next()
from pwn import *
from Crypto.Util.number import *


debug = True
r = remote("168.119.108.148", 13010, level = 'debug' if debug else None)

#https://crypto.stackexchange.com/questions/27904/how-to-determine-the-order-of-an-elliptic-curve-group-from-its-parameters
def V_n(n, t, q):
    a = 2
    b = t
    for i in range(2, n+1):
        a, b = b, t*b-q*a
    return b


while True:
    r.recvuntil('p = ')
    p = int(r.recvline())
    assert isPrime(p)

    r.recvuntil('k = ')
    k = int(r.recvline())

    r.recvuntil("What's the number of elements of E over finite field GF(p**n) where n = ")
    n = int(r.recvline(keepends=False)[:-1])
    print(n)

    t = p + 1 - k

    payload = p^n + 1 - V_n(n, t, p)

    r.sendline(str(payload))

    print(r.recvline())

#b'Congrats, you got the flag: .:: ASIS{wH47_iZ_mY_5P1R!TuAL_4NiMal!???} ::.\n'
from pwn import *
from Crypto.Util.number import *
import owiener
from math import isqrt
from sage.all import Integer

debug = True

r = remote("crypto.chal.csaw.io", 5008, level = 'debug') if debug else remote("crypto.chal.csaw.io", 5008)

#==================Part One==================
r.recvuntil('N = ')
n = int(r.recvline())
r.recvuntil('e = ')
e = int(r.recvline())
r.recvuntil('c = ')
c = int(r.recvline())

#https://github.com/orisano/owiener
d = owiener.attack(e, n)

if d is None:
    print("Failed")
else:
    print("Hacked d={}".format(d))

m = long_to_bytes(pow(c, d, n))
#m = b'Wiener wiener chicken dinner'

r.recvuntil("What is the plaintext?\r\n")
r.sendline(m)

#==================Part Two==================
r.recvuntil('N = ')
n = int(r.recvline())
r.recvuntil('e = ')
e = int(r.recvline())
r.recvuntil('c = ')
c = int(r.recvline())

def factorize(n):
    """
    Recovers the prime factors from a modulus using Fermat's factorization method.
    :param n: the modulus
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    a = isqrt(n)
    b = a * a - n
    while b < 0 or isqrt(b) ** 2 != b:
        a += 1
        b = a * a - n

    p = a - isqrt(b)
    q = n // p
    if p * q == n:
        return p, q

#https://en.wikipedia.org/wiki/Sexy_prime
#Sexy primes differ by 6, since factors are too close, Fermat's factorization can be used

factors = factorize(n)
p, q = factors[0], factors[1]
totient = (p-1)*(q-1)
d = inverse(e, totient)
m = long_to_bytes(pow(c, d, n))
#m = b'Who came up with this math term anyway?'

r.recvuntil("What is the plaintext?\r\n")
r.sendline(m)

#==================Part Three==================

r.recvuntil('N = ')
n = int(r.recvline())
r.recvuntil('e = ')
e = int(r.recvline())
r.recvuntil('c = ')
c = int(r.recvline())

def lsbOracle(c):
    temp = r.recvline()
    print(f"Temp is {temp}")
    if (temp == b'Would you like to continue? (yes/no)\r\n'):
        r.sendline(b"yes")
    r.recvuntil(b'What would you like to decrypt? (please respond with an integer)\r\n')
    r.sendline(str(c))
    r.recvuntil('The oracle responds with: ')
    bit = int(r.recvline())
    print(f"Bit is {bit}")
    return bit

def attack(n, e, c):
    """
    Recovers the plaintext from the ciphertext using the LSB oracle attack.
    :param n: the modulus
    :param e: the public exponent
    :param c: the encrypted message
    :param oracle: a function which returns the last bit of a plaintext for a given ciphertext
    :return: the plaintext
    """
    left = Integer(0)
    right = Integer(n)
    while right - left > 1:
        c = (c * pow(2, e, n)) % n
        if lsbOracle(c) == 0:
            right = (right + left) / 2
        else:
            left = (right + left) / 2

    return int(right)

m = attack(n, e, c)
print(m, long_to_bytes(m))
#m = b'Totally did not mean to put an oracle there'

r.recvuntil(b'What would you like to decrypt? (please respond with an integer)\r\n')
r.sendline("1")
r.recvuntil(b'Would you like to continue? (yes/no)\r\n')
r.sendline(b'no')

r.recvuntil(b'What is the plaintext?\r\n')
r.sendline(m)

#==================Part Four==================

r.recvuntil('N = ')
n = int(r.recvline())
r.recvuntil('e = ')
e = int(r.recvline())
r.recvuntil('d0 = ')
d0 = int(r.recvline())
r.recvuntil('c = ')
c = int(r.recvline())
r.recvuntil('d0bits = ')
d0bits = int(r.recvline())
r.recvuntil('nBits = ')
nBits = int(r.recvline())

#Partial Private Key Exposure
#https://www.jianshu.com/p/d8d2ce53041b
def partial_p(p0, kbits, n):
    PR.<x> = PolynomialRing(Zmod(n))
    nbits = n.nbits()
    f = 2^kbits*x + p0
    f = f.monic()
    roots = f.small_roots(X=2^(nbits//2-kbits), beta=0.3)  # find root < 2^(nbits//2-kbits) with factor >= n^0.3
    if roots:
        x0 = roots[0]
        p = gcd(2^kbits*x0 + p0, n)
        return ZZ(p)
def find_p(d0, kbits, e, n):
    X = var('X')
    for k in range(1, e+1):
        results = solve_mod([e*d0*X - k*X*(n-X+1) + k*n == X], 2^kbits)
        for x in results:
            p0 = ZZ(x[0])
            p = partial_p(p0, kbits, n)
            if p:
                return p

p = find_p(Integer(d0), Integer(d0bits), Integer(e), Integer(n))
print ("found p: %d" % p)
assert n % p == 0
q = n//p
d = inverse_mod(e, (p-1)*(q-1))

m = long_to_bytes(pow(int(c), int(d), int(n)))

r.recvuntil(b'What is the plaintext?\r\n')
r.sendline(m)
print(r.recvall())

#b'Success!\r\n\r\nCongrats on passing the RSA Pop Quiz! Here is your flag: flag{l00K5_L1K3_y0u_H4v3_p4223D_7h3_D1ff1Cul7_r54_p0p_Kw12_w17H_fLy1N9_C0L0r2}\r\n\r\n'

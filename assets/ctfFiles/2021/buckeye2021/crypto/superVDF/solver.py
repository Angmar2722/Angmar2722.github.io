from pwn import *
from Crypto.Util.number import *

debug = False
r = remote("crypto.chall.pwnoh.io", 13376, level = 'debug' if debug else None)

payload = 1

r.recvuntil('n = ')
n = int(r.recvline().decode())

#Pollard's p-1 factorisation algorithm
def factor(n):
    a = 2
    b = 2
    while True:
        if b % 10000 == 0:
            pass
            
        a = pow(a, b, n)
            
        p = GCD(a - 1, n)
        if 1 < p < n:
            print("FOUND prime factor")
            return p
            
        b += 1

p = factor(n)
q = n // p
assert n == p * q

#Please calculate (59 ** 59 ** 59 ** 59 ** 1333337) % n)

#https://math.stackexchange.com/questions/3558102/how-to-compute-333-phantom-bmod-46-for-pow/3559055
from sympy.ntheory import totient

assert GCD(59, n) == 1

phi = (p - 1) * (q - 1)
secondPhi = totient(phi)
thirdPhi = totient(secondPhi)
fourthPhi = totient(thirdPhi)

answer = pow(59, (pow(59, (pow(59, (pow(59, 1333337 % fourthPhi, thirdPhi)), secondPhi)), phi)), n)
r.sendlineafter('>>> ', str(answer))

print(r.recvall())
#b"WTF do you own a supercomputer? Here's your flag:\nbuckeye{phee_phi_pho_phum_v3ry_stup1d_puzzle}\n"
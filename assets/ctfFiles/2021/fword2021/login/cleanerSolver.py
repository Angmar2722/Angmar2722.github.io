from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, getPrime, GCD
import os, hashlib, sys, signal
#https://github.com/stephenbradshaw/hlextend
import hlextend
from math import gcd
from sympy import isprime

local = False
debug = True

if local:
    r = process(["python3", "local.py"], level='debug') if debug else process(["python3", "local.py"])
else:
    r = remote("52.149.135.130", 4871, level = 'debug') if debug else remote("52.149.135.130", 4871)


r.sendlineafter('> ', b'1')

user = b'hi'
r.sendlineafter('Username : ', user)
r.recvuntil(b'Account created.\n')

username = r.recvline()[11:].decode().strip()
password = r.recvline()[11:].decode().strip()
proof = r.recvline()[8:].decode().strip()

sha = hlextend.new('sha256')
extension = sha.extend(';is_admin=true', ';hi;is_admin=false', 16, password)[1:-14]

r.sendlineafter('> ', b'2')
r.sendlineafter('Username : ', eval(f"b'{extension}'").hex())
passwdPayload = sha.hexdigest()
r.sendlineafter('Password : ', passwdPayload.encode())
proofPayload = b'is_admin=true'
r.sendlineafter('Proof : ', proofPayload.hex().encode())

print(r.recvline())

e = int(r.recvline()[4:].decode().strip(), 16)
d = int(r.recvline()[4:].decode().strip(), 16)
inversePQ = int(r.recvline()[16:].decode().strip(), 16)


upper_lim = min(e, d)
ks = []

for k in range(2, upper_lim):
	if (e * d - 1) % k == 0 and ((e * d - 1) // k).bit_length() <= 2048:
		ks.append(k)

# print("[*] Possible number of k values = ", len(ks)) # 1
print(f"List of possible Ks = {ks}")

#https://gist.github.com/n-ari/a2db9af7fd3c172e4fa65b923a66beff
for k in ks:
    print(f"K checked is {k}")
    phi = (e*d - 1) // k
    c1 = (phi - 1) * inversePQ + 1
    
    factors = [c1]
    for i in range(2, 11):
        factors.append(pow(i, phi, c1) - 1)
    q = gcd(*factors)

    if q.bit_length() != 1024 or not isprime(q): continue
    print(f"q : {q} and isprime = {isprime(q)}")

    p = phi // (q - 1) + 1
    if d != inverse(e, (p-1)*(q-1)) or p.bit_length() != 1024 or not isprime(p): continue
    print(f"p : {p} and isprime = {isprime(p)}")

    if inversePQ != inverse(p, q) : continue
    break

n = p*q
print(n)
message_to_sign = b"https://twitter.com/CTFCreators"
payload = hex(pow(bytes_to_long(message_to_sign), d, int(n)))[2:]

r.sendlineafter('Enter your signature : ', payload)
print(r.recvline())



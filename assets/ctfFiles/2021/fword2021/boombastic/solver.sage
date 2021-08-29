from pwn import *
import json
from Crypto.Util.number import getStrongPrime, inverse
import hashlib, sys, os, signal, random

local = False
debug = False

if local:
    tube = process(["python3", "server.py"], level='debug') if debug else process(["python3", "server.py"])
else:
    tube = remote("52.149.135.130", 4872, level = 'debug') if debug else remote("52.149.135.130", 4872)

tube.sendlineafter("> ", b"2")
tube.recvline()
output = json.loads(tube.recvline()[14:].decode())
s, r, p = int(output['s'], 16), int(output['r'], 16), int(output['p'], 16)

y, k = gens(PolynomialRing(Zmod(p), ['y','k']))
ideal = [r - (y^2 - 1)*k^2, s - (y + 1)*k]

I = Ideal(ideal)
B = I.groebner_basis()

#print(B[0])
#print(B[1])

k = int(-B[1](k = 0)) % p
secret = inverse_mod(k, p)
print(secret)
y = int((-B[0](y = 0))) % p
#print(y)

def get_ticket(code):
    y = int(hashlib.sha256(code.encode()).hexdigest(),16)
    r = ((y**2 - 1) * (inverse(secret**2, p))) % p
    s = ((1 + y) * (inverse(secret, p))) % p
    return str({'s': hex(s), 'r': hex(r), 'p': hex(p)})

payload = get_ticket("Boombastic").replace("'", '"')

tube.sendlineafter("> ", b"1")
tube.sendlineafter('Enter the magic word : ', payload.encode())
print(tube.recvline())
exit()
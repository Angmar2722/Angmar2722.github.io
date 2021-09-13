from pwn import *
from Crypto.Util.number import *
from random import randint
from math import gcd

debug = False

tube = remote("crypto.chal.csaw.io", 5006, level = 'debug') if debug else remote("crypto.chal.csaw.io", 5006)

tube.recvuntil("Server's public key (p,g,y): ")
pubKey = tube.recvline().split()
p, g, y = int(pubKey[0]), int(pubKey[1]), int(pubKey[2])

g = 3
MASK = 2**1024 - 1

#https://blog.y011d4.com/20210424-cyber-apocalypse-ctf-writeup/#forge-of-empires
message = b'Felicity Cisco both'
message += (256 - len(message)) * b"\x00"
assert b"Felicity Cisco both" in bytes.fromhex(message.hex())
message = int(message.hex(), 16)

while True:
    t = randint(2, p - 2)
    if gcd(t, p - 1) != 1:
        continue
    r = pow(g, t, p) * y % p
    s = (-r) % (p - 1)
    m = t * s % (p - 1)
    break

message += m

tube.recvuntil(b'Answer: \r\n')
tube.sendline(hex(message)[2:])
tube.recvuntil(b'r: \r\n')
tube.sendline(str(r))
tube.recvuntil(b's: \r\n')
tube.sendline(str(s))
print(tube.recvall())

#b'I see you are a fan of Arrow!\r\nflag{7h3_4rr0wv3r53_15_4w350M3!}\r\n\r\nThanks to Cyber Apocalypse 2021 for the inspiration for this challenge!\r\n'

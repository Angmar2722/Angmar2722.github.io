from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

local = False
debug = False

if local:
    r = process(["python3", "leaky_blinders.py"], level='debug') if debug else process(["python3", "leaky_blinders.py"])
else:
    r = remote("52.149.135.130", 4869, level = 'debug') if debug else remote("52.149.135.130", 4869)

key = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeef")

def xor(a, b):
    return bytearray([a[i % len(a)] ^ b[i % len(b)] for i in range(max(len(a), len(b)))])

def encrypt(msg):
    aes = AES.new(key, AES.MODE_ECB)
    if len(msg) % 16 != 0:
        msg = pad(msg, 16)
    cipher = aes.encrypt(msg)
    cipher = xor(cipher, key)
    return cipher

ct = encrypt(b"FwordCTF{leaky_blinders}")

r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"Key : ", b"deadbeefdeadbeefdeadbeefdeadbeef")
r.sendlineafter(b"Ciphertext : ", ct.hex())
print(r.recvline())
exit()
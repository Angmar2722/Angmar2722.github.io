from pwn import *
from Crypto.Util.number import *
from Crypto.Cipher import AES


debug = True
r = remote("crypto.chall.pwnoh.io", 13374, level = 'debug' if debug else None)

r.recvuntil('p = ')
p = int(r.recvline())
assert isPrime(p)

g = 5
r.recvuntil('A = ')
A = int(r.recvline())

B = pow(g, 57, p)
ss = pow(A, 57, p)

r.sendlineafter('Give me your public key B: ', str(B))
r.recvuntil('ciphertext = ')
ct = r.recvline(keepends=False).decode()

key = hashlib.sha1(long_to_bytes(ss)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(bytes.fromhex(ct)))
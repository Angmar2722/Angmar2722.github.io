from pwn import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import size, long_to_bytes
import hashlib

#https://crypto.stackexchange.com/questions/82078/curve25519-montgomery-curves-points-with-order-8

debug = True
r = remote("crypto.chall.pwnoh.io", 13373, level = 'debug' if debug else None)

x = 57896044618658097711785492504343953926634992332820282019728792003956564819948

r.sendlineafter('x: ', str(x))

ct = bytes.fromhex(r.recvline(keepends=False).decode())

a1 = 57896044618658097711785492504343953926634992332820282019728792003956564819948
a2 = 0

k1 = hashlib.sha1(long_to_bytes(a1)).digest()[:16]
k2 = hashlib.sha1(long_to_bytes(a2)).digest()[:16]
cipher1 = AES.new(k1, AES.MODE_ECB)
cipher2 = AES.new(k2, AES.MODE_ECB)
pt1 = cipher1.decrypt(pad(ct, 16))
pt2 = cipher2.decrypt(pad(ct, 16))
print(pt1)
print(pt2)

#b'buckeye{p01nt5_0f_l0w_0rd3r}\x04\x04\x04\x04\xb9+\xc6I\xfd\x89\x7f\xcb\x92\xaeQC\x9fw,\x1f'
#b'\xd3&R\xddu~\xa1IL\xee \xf4\x9fE>A&I\xb5\x88P<LW\xcc\xee\x8d\xed\x9e\n\xaf!n\x9d\x9d\xbe\xdd\xe2\xd5\xb6TU\x85\xd0\x9er%\xc9'
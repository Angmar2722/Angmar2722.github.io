from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256

local = False
debug = False

if local:
    r = process(["python3", "test.py"], level='debug') if debug else process(["python3", "server.py"])
else:
    r = remote("tasks.yauzactf.com", 30011, level = 'debug') if debug else remote("tasks.yauzactf.com", 30011)

def getChallenge():
    r.sendlineafter("> ", b"2")
    r.recvline()
    challenge = r.recvline()
    r.sendlineafter('sign: ', b"1001")
    return int(challenge.decode())

def signMessage(m):
    r.sendlineafter("> ", b"1")
    r.sendlineafter('msg: ', str(m).encode())
    signature = r.recvline()
    return signature

def checkSignature(s):
    r.sendlineafter("> ", b"2")
    r.sendlineafter('sign: ', str(s).encode())
    return r.recvline()

challenge = getChallenge()

def sha2(x):
    hash = SHA256.new()
    hash.update(x)
    return hash.digest()

def byten(x, n):
    return (x >> (n * 8)) & 0xFF

def mask(n):
    return (1 << n) - 1

def rotate(x, n, s):
    return ((x >> (s - n)) | (x << n)) & mask(s)

def invRotate(x, n, s):
    return ((x << (s - n)) | (x >> n)) & mask(s)

def scramble(x):
    magic = 0xC3A569C3A569C3A569C3A569C3A569C33C965A3C965A3C965A3C965A3C965A3C
    for i in range(32):
        x = rotate(x, 27, 256) ^ rotate(magic, i, 256)
    return x

def invScramble(x):
    magic = 0xC3A569C3A569C3A569C3A569C3A569C33C965A3C965A3C965A3C965A3C965A3C
    for i in range(31, -1, -1):
        x = invRotate(x ^ rotate(magic, i, 256), 27, 256)
    return x

privateKeyBytes = long_to_bytes(signMessage(invScramble(0)))
privateKey = []

for i in range(0, len(privateKeyBytes), 32):
    privateKey.append(bytes_to_long(privateKeyBytes[i:i+32]))

print(challenge)
print(privateKey)

def sign(x, key):
    parts = [byten(x, i) for i in range(16)]

    digest = [long_to_bytes(y) for y in key]
    for i in range(16):
        for j in range(parts[i]):
            digest[i] = sha2(digest[i])

    return digest

def do_signature(x, private):
    signature = sign(scramble(x), private)
    return bytes_to_long(b''.join(signature))

def verify(x, sign, public):
    parts = [255 - byten(x, i) for i in range(16)]

    digest = list(sign)
    for i in range(16):
        for j in range(parts[i]):
            digest[i] = sha2(digest[i])
        if digest[i] != long_to_bytes(public[i]):
            return False
    return True

def do_verify(x, signature, public):
    signature = long_to_bytes(signature, 256*16//8)
    signature = [signature[i*32:(i + 1)*32] for i in range(16)]
    return verify(scramble(x), signature, public)
    
public = [long_to_bytes(y) for y in privateKey]
for i in range(16):
    for j in range(255):
        public[i] = sha2(public[i])
public = [bytes_to_long(y) for y in public]

forgedSignature = do_signature(challenge, privateKey)

assert do_verify(challenge, forgedSignature, public) 

print(checkSignature(forgedSignature))
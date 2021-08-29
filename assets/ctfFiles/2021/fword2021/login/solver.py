from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, getPrime, GCD
import os, hashlib, sys, signal
from math import gcd
from sympy import isprime
from re import match
from math import ceil

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


#https://github.com/stephenbradshaw/hlextend
class Hash(object):
    '''Parent class for hash functions'''


    def hash(self, message):
        '''Normal input for data into hash function'''

        length = bin(len(message) * 8)[2:].rjust(self._blockSize, "0")
        
        while len(message) > self._blockSize:            
            self._transform(''.join([bin(ord(a))[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        message = self.__hashBinaryPad(message, length)
        

        for a in range(len(message) // self._b2):
            self._transform(message[a * self._b2:a * self._b2 + self._b2])



    def extend(self, appendData, knownData, secretLength, startHash, raw=False):
        '''Hash length extension input for data into hash function'''

        self.__checkInput(secretLength, startHash)
        self.__setStartingHash(startHash)        
        
        extendLength = self.__hashGetExtendLength(secretLength, knownData, appendData)        

        message = appendData

        while len(message) > self._blockSize:
            self._transform(''.join([bin(ord(a))[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        message = self.__hashBinaryPad(message, extendLength)        

        for i in range(len(message) // self._b2):
            self._transform(message[i * self._b2:i * self._b2 + self._b2])

        return self.__hashGetPadData(secretLength, knownData, appendData, raw=raw)


    def hexdigest(self):
        '''Outputs hash data in hexlified format'''
        return ''.join( [ (('%0' + str(self._b1) + 'x') % (a)) for a in self.__digest()])


    def __init__(self):
        # pre calculate some values that get used a lot
        self._b1 = self._blockSize/8
        self._b2 = self._blockSize*8



    def __digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]


    def __setStartingHash(self, startHash):
        c = 0
        hashVals = [ int(startHash[a:a+int(self._b1)],base=16) for a in range(0,len(startHash), int(self._b1)) ]
        for hv in [ a for a in dir(self) if match('^_h\d+$', a) ]:
            self.__setattr__(hv, hashVals[c])        
            c+=1


    def __checkInput(self, secretLength, startHash):
        if not isinstance(secretLength, int):
            raise TypeError('secretLength must be a valid integer')
        if secretLength < 1:
            raise ValueError('secretLength must be grater than 0')
        if not match('^[a-fA-F0-9]{' + str(len(self.hexdigest())) + '}$', startHash):
            raise ValueError('startHash must be a string of length ' + str(len(self.hexdigest())) + ' in hexlified format')
        

    def __byter(self, byteVal):
        '''Helper function to return usable values for hash extension append data'''
        if byteVal < 0x20 or byteVal > 0x7e:
            return '\\x%02x' %(byteVal)
        else:    
            return chr(byteVal)


    def __binToByte(self, binary):
        '''Convert a binary string to a byte string'''
        return ''.join([ chr(int(binary[a:a+8],base=2)) for a in range(0,len(binary),8) ])



    def __hashGetExtendLength(self, secretLength, knownData, appendData):
        '''Length function for hash length extension attacks'''
        # binary length (secretLength + len(knownData) + size of binarysize+1) rounded to a multiple of blockSize + length of appended data
        originalHashLength = int(ceil((secretLength+len(knownData)+self._b1+1)/float(self._blockSize)) * self._blockSize) 
        newHashLength = originalHashLength + len(appendData) 
        return bin(newHashLength * 8)[2:].rjust(self._blockSize, "0")


    def __hashGetPadData(self, secretLength, knownData, appendData, raw=False):
        '''Return append value for hash extension attack'''    
        originalHashLength = bin((secretLength+len(knownData)) * 8)[2:].rjust(self._blockSize, "0")    
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in knownData) + "1"
        padData += "0" * (((self._blockSize*7) - (len(padData)+(secretLength*8)) % self._b2) % self._b2) + originalHashLength 
        if not raw:
            return ''.join([ self.__byter(int(padData[a:a+8],base=2)) for a in range(0,len(padData),8) ]) + appendData
        else:
            return self.__binToByte(padData) + appendData    


    def __hashBinaryPad(self, message, length):
        '''Pads the final blockSize block with \x80, zeros, and the length, converts to binary'''
        message = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in message) + "1"    
        message += "0" * (((self._blockSize*7) - len(message) % self._b2) % self._b2) + length
        return message


class SHA256 (Hash):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    _blockSize = 64


    def _transform(self, chunk):
        rrot = lambda x, n: (x >> n) | (x << (32 - n))
        w = []

        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in range(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~ e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
        self._h5 = (self._h5 + f) & 0xffffffff
        self._h6 = (self._h6 + g) & 0xffffffff
        self._h7 = (self._h7 + h) & 0xffffffff


def new(algorithm):
    obj = {
        'sha256': SHA256,
    }[algorithm]()
    return obj


def sha256():
    ''' Returns a new sha256 hash object '''
    return new('sha256', )


sha = new('sha256')
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



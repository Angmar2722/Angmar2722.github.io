import random
import string
import time
from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from bitstring import BitArray, Bits
import binascii
import sys
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


ALL_ZEROS = b'\x00'*16
GCM_BITS_PER_BLOCK = 128


def check_correctness(keyset, nonce, ct):
    flag = True

    for i in range(len(keyset)):
        aesgcm = AESGCM(key)
        try:
            aesgcm.decrypt(nonce, ct, None)
        except InvalidTag:
            print('key %s failed' % i)
            flag = False

    if flag:
        print("All %s keys decrypted the ciphertext" % len(keyset))



def pad(a):
    if len(a) < GCM_BITS_PER_BLOCK:
        diff = GCM_BITS_PER_BLOCK - len(a)
        zeros = ['0'] * diff
        a = a + zeros
    return a



def bytes_to_element(val, field, a):
    bits = BitArray(val)
    result = field.fetch_int(0)
    for i in range(len(bits)):
        if bits[i]:
            result += a^i
    return result



def multi_collide_gcm(keyset, nonce, tag, first_block=None, use_magma=False):

    # initialize matrix and vector spaces
    P.<x> = PolynomialRing(GF(2))
    p = x^128 + x^7 + x^2 + x + 1
    GFghash.<a> = GF(2^128,'x',modulus=p)
    if use_magma:
        t = "p:=IrreducibleLowTermGF2Polynomial(128); GFghash<a> := ext<GF(2) | p>;"
        magma.eval(t)
    else:
        R = PolynomialRing(GFghash, 'x')

    # encode length as lens
    if first_block is not None:
        ctbitlen = (len(keyset) + 1) * GCM_BITS_PER_BLOCK
    else:
        ctbitlen = len(keyset) * GCM_BITS_PER_BLOCK
    adbitlen = 0
    lens = (adbitlen << 64) | ctbitlen
    lens_byte = int(lens).to_bytes(16,byteorder='big')
    lens_bf = bytes_to_element(lens_byte, GFghash, a)

    # increment nonce
    nonce_plus = int((int.from_bytes(nonce,'big') << 32) | 1).to_bytes(16,'big')

    # encode fixed ciphertext block and tag
    if first_block is not None:
        block_bf = bytes_to_element(first_block, GFghash, a)
    tag_bf = bytes_to_element(tag, GFghash, a)
    keyset_len = len(keyset)

    if use_magma:
        I = []
        V = []
    else:
        pairs = []

    for k in keyset:
        # compute H
        aes = AES.new(k, AES.MODE_ECB)
        H = aes.encrypt(ALL_ZEROS)
        h_bf = bytes_to_element(H, GFghash, a)

        # compute P
        P = aes.encrypt(nonce_plus)
        p_bf = bytes_to_element(P, GFghash, a)

        if first_block is not None:
            # assign (lens * H) + P + T + (C1 * H^{k+2}) to b
            b = (lens_bf * h_bf) + p_bf + tag_bf + (block_bf * h_bf^(keyset_len+2))
        else:
            # assign (lens * H) + P + T to b
            b = (lens_bf * h_bf) + p_bf + tag_bf

        # get pair (H, b*(H^-2))
        y =  b * h_bf^-2
        if use_magma:
            I.append(h_bf)
            V.append(y)
        else:
            pairs.append((h_bf, y))

    # compute Lagrange interpolation
    if use_magma:
        f = magma("Interpolation(%s,%s)" % (I,V)).sage()
    else:
        f = R.lagrange_polynomial(pairs)
    coeffs = f.list()
    coeffs.reverse()

    # get ciphertext
    if first_block is not None:
        ct = list(map(str, block_bf.polynomial().list()))
        ct_pad = pad(ct)
        ct = Bits(bin=''.join(ct_pad))
    else:
        ct = ''
    
    for i in range(len(coeffs)):
        ct_i = list(map(str, coeffs[i].polynomial().list()))
        ct_pad = pad(ct_i)
        ct_i = Bits(bin=''.join(ct_pad))
        ct += ct_i
    ct = ct.bytes
    
    return ct+tag


keyList = [a + b + c for a in string.ascii_lowercase for b in string.ascii_lowercase for c in string.ascii_lowercase]
#keyList = [a + b for a in string.ascii_lowercase for b in string.ascii_lowercase]

scryptedKeyList = []

for key in keyList:
    kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
    key = kdf.derive(key.encode())
    scryptedKeyList.append(key)

collisionLength = 1000
chunks = [scryptedKeyList[x:x+collisionLength] for x in range(0, len(scryptedKeyList), collisionLength)]

first_block = b'\x01'
nonce = b'\x01'*12
tag = b'\x00'*16

cipherList = []

for keyset in chunks:
    #print('hi')
    payloadCT = multi_collide_gcm(keyset, nonce, tag, first_block=first_block)
    cipherList.append(payloadCT)
    
print(cipherList)

#with open("cipherList.txt", "w") as f:
    #f.write(str(cipherList))

from bitstring import BitArray, Bits
from Crypto.Cipher import AES 
from Crypto.Util.number import *
from test import *
from pwn import *
from tqdm import tqdm
import string
import os
from tqdm.contrib.concurrent import process_map, thread_map  

debug = False
local = False


while True:

    try:
        if local:
            r = process(["python3", "testServer.py"], level='debug') if debug else process(["python3", "testServer.py"])
        else:
            r = remote("good-hash.chal.perfect.blue", 1337, level = 'debug') if debug else remote("good-hash.chal.perfect.blue", 1337)

        r.recvuntil('Body: ')
        token = json.loads(r.recvline()[:-1].decode())['token']
        r.recvuntil('Hash: ')
        hash = r.recvline(keepends=False).decode()
        nonce = json.dumps({"token": token, "admin": False}).encode()
        print(f"Nonce fetched from server is {nonce}")


        def bytes_to_element(val, field, a): 
            bits = BitArray(val) 
            result = field.fetch_int(0) 
            for i in range(len(bits)): 
                if bits[i]: 
                    result += a^i 
            return result

        P.<x> = PolynomialRing(GF(2))
        p = x^128 + x^7 + x^2 + x + 1
        GFghash.<a> = GF(2^128,'x',modulus=p)

        key = b"goodhashGOODHASH"

        hash_subkey = AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*16)
        H_bf = bytes_to_element(hash_subkey, GFghash, a)
        #nonce = b'{"token": "d3271b732403d742fa1e617d24c741c8", "admin": false}'

        fill = (16 - (len(nonce) % 16)) % 16 + 8
        ghash_in = (nonce +
                        b'\x00' * fill +
                        long_to_bytes(8 * len(nonce), 8))

        a1, a2, a3, a4, a5 = [ghash_in[i:i+16] for i in range(0, len(ghash_in), 16)]

        assert all(len(b) == 16 for b in [a1, a2, a3, a4, a5])
        a1_bf, a2_bf, a3_bf, a4_bf, a5_bf = [bytes_to_element(x, GFghash, a) for x in [a1, a2, a3, a4, a5]]

        a4_prime_bf = bytes_to_element(b'dmin": true }', GFghash, a)
        k = (a2_bf*H_bf^2 + a4_bf + a3_bf*H_bf - a4_prime_bf) / H_bf

        def iterate(n):
            a3_prime, a3_prime_bf = a3, a3_bf
            for i in tqdm(range(n)):
                a2_prime_bf = (k - a3_prime_bf) / H_bf
                a2_prime = long_to_bytes(BitArray(a2_prime_bf.polynomial().list()).uint)
                a4_prime = long_to_bytes(BitArray(a4_prime_bf.polynomial().list()).uint)
                if all(32 <= i <= 126 for i in a2_prime):
                    print("-"*25 + "nonces" + "-"*25)
                    print(a1, a2, a3, a4, a5)
                    print(a1, a2_prime, a3_prime, a4_prime, a5)

                    print("-"*25 + "computed hashes" + "-"*25)
                    print(long_to_bytes(BitArray((a1_bf*H_bf^5 + a2_bf*H_bf^4 + a3_bf*H_bf^3 + a4_bf*H_bf^2 + a5_bf*H_bf).polynomial().list()).uint))
                    print(long_to_bytes(BitArray((a1_bf*H_bf^5 + a2_prime_bf*H_bf^4 + a3_prime_bf*H_bf^3 + a4_prime_bf*H_bf^2 + a5_bf*H_bf).polynomial().list()).uint))

                    assert a1_bf*H_bf^5 + a2_bf*H_bf^4 + a3_bf*H_bf^3 + a4_bf*H_bf^2 + a5_bf*H_bf == a1_bf*H_bf^5 + a2_prime_bf*H_bf^4 + a3_prime_bf*H_bf^3 + a4_prime_bf*H_bf^2 + a5_bf*H_bf

                    print("-"*25 + "ciphertexts" + "-"*25)

                    CT1 = digest((a1 + a2 + a3 + a4)[:-3])
                    CT2 = digest(a1 + a2_prime + a3_prime + a4_prime)
                    print(f"CT1 is {CT1}")
                    print(f"CT2 is {CT2}")

                    try:
                        assert CT1 == CT2
                    except AssertionError as e:
                        print(e)
                        continue

                    nonceToSend = a1 + a2_prime + a3_prime + a4_prime

                    print("-"*50)
                    print(f"Nonce to send is {nonceToSend}")

                    print(" "*20+"Getting flag, fingers crossed ...... :)   ")
                    r.sendlineafter('> ', nonceToSend)
                    print(r.recvall())
                else:
                    a3_prime = os.urandom(5).hex().encode() + b'b", "a'
                    a3_prime_bf = bytes_to_element(a3_prime, GFghash, a)

        thread_map(iterate, [10000]*10, max_workers=150)

    except AssertionError:
        print("Loop Ran Out!!!")
        continue

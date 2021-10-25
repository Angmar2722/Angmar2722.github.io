import os
from Crypto.Util.number import *
from pwn import *
from sys import stderr
from random import choice, getrandbits
from random import randrange

#https://gist.github.com/keltecc/b5fbd533d2f203e810b43c26ff9d17cc

def miller_rabin(bases, n):
    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    ZmodN = Zmod(n)

    for b in map(ZmodN, bases):
        x = b ^ s
        if x == 1 or x == -1:
            continue
        for _ in range(r - 1):
            x = x ^ 2
            if x == -1:
                break
        else:
            return False
    
    return True


def search_pseudoprime(bases, coeffs, rlen, iters, verbose=False):
    modules = [4 * b for b in bases]

    residues = dict()

    for b, m in zip(bases, modules):
        residues[b] = set()
        for p in primes(3, 1024 * max(bases)):
            if kronecker(b, p) == -1:
                residues[b].add(p % m)

    sets = dict()

    for b, m in zip(bases, modules):
        s = []
        for c in coeffs:
            s.append({(inverse_mod(c, m) * (r + c - 1)) % m for r in residues[b]})
        sets[b] = list(set.intersection(*s))

    # only support this
    assert len(coeffs) == 3

    coeffs_inv = [
        1, 
        coeffs[1] - inverse_mod(coeffs[2], coeffs[1]), 
        coeffs[2] - inverse_mod(coeffs[1], coeffs[2])
    ]

    mod = lcm(modules + coeffs)

    while True:
        choices = [choice(sets[b]) for b in bases]

        rem = crt(
            choices + coeffs_inv,
            bases + coeffs
        )

        if verbose:
            print(f'[*] Searching pseudoprime...', file=stderr)

        for i in range(iters):
            if verbose and i % 10000 == 0:
                print(f'{i}...')

            p1 = getrandbits(rlen) * mod + rem
            p2 = (p1 - 1) * coeffs[1] + 1
            p3 = (p1 - 1) * coeffs[2] + 1

            pprime = p1 * p2 * p3
            
            if miller_rabin(bases, pprime):
                break
        else:
            if verbose:
                print(f'[-] Failed to find pseudoprime, trying with another choices...', file=stderr)
            
            continue

        if verbose:
            print(f'[+] Found pseudoprime!', file=stderr)
            print(f'[+] P = {pprime}', file=stderr)

        return pprime, [p1, p2, p3]

def getMillerRabinPseudoprime():
    rlen = 64
    iters = 30000
    verbose = True

    bases = list(primes(50))
    coeffs = [1, 313, 353]

    pprime, divisors = search_pseudoprime(bases, coeffs, rlen, iters, verbose)

    assert not is_prime(pprime) and \
            miller_rabin(bases, pprime)

    print(f"Successfully generated pseudoprime : {pprime}")
    print(f"Its divisors are {divisors}")
    print(f"Its bit length is {pprime.nbits()}")

    return pprime, divisors

mrPPrime, mrPPrimeDivisors = getMillerRabinPseudoprime()
assert(256 <= mrPPrime.nbits() <= 512)

def is_prime(n, rounds=32):
    return all(pow(randrange(2, n), n - 1, n) == 1 for _ in range(rounds))

for i in range(50): assert is_prime(mrPPrime)


debug = False
local = False

if local:
    r = process(["python3", "chall.py"], level='debug' if debug else None)
else:
    r = remote("crypto.chall.pwnoh.io", 13375, level = 'debug' if debug else None)

r.sendlineafter('Give me a prime number: ', str(mrPPrime))

r.recvuntil('Have some ciphertexts:\n')
ctList = list(str(r.recvline(keepends=False).decode()) for i in range(32))
assert len(ctList) == 32

ctBinList = list(bin(bytes_to_long(bytes.fromhex(ct)))[2:] for ct in ctList)

bitFreqList = []
for i in range(102*8):
    temp = []
    for ct in ctBinList:
        if (len(ct) != 102*8):
            ct = "0" * (102*8 - len(ct)) + ct
        assert len(ct) == 102*8
        temp.append(ct[i])
    bitFreqList.append(temp)

toSend = ""

def most_frequent(List):
    return max(set(List), key = List.count)

toSend = long_to_bytes(int(''.join(list(most_frequent(bit) for bit in bitFreqList)), 2))
print(f"Found secret strin, it is {toSend}")

r.sendline(toSend)
print(r.recvall())

#b"Guess the plaintext:\nCongrats! Here's the flag: b'buckeye{f3rm4t_l13d_t0_m3_0mg}'\n"

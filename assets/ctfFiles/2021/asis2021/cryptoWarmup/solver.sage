from Crypto.Util.number import *
import string
import ast

with open("output.txt", "r") as f:
    temp = f.read()

enc = temp[6:]
p = len(enc)
assert isPrime(p)

def getAllPrimiteRoots(n):
    f = Integers(n)
    firstGenerator = f(primitive_root(n))
    totient = euler_phi(n)
    return [firstGenerator ^ i for i in range(1, totient) if gcd(i, totient) == 1]
    
primitiveRoots = getAllPrimiteRoots(p)

for s in primitiveRoots:
    possibleFlag = 'AS'
    for i in range(2, 5):
        possibleFlag += enc[Integers(p)(i).log(s) + 1]
    if possibleFlag != "ASIS{":
        continue
    for i in range(5, p-1):
        possibleFlag += enc[Integers(p)(i).log(s) + 1]
    print(possibleFlag[:64])

#ASIS{_how_d3CrYpt_Th1S_h0m3_m4dE_anD_wEird_CrYp70_5yST3M?!!!!!!}



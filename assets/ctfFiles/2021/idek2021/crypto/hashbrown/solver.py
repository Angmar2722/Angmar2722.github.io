import string
import hashlib
import random
from tqdm import tqdm

possibleChars = list(chr(i).encode() for i in range(32, 127))

for c1 in tqdm(possibleChars):
    for c2 in possibleChars:
        for c3 in possibleChars:
            for c4 in possibleChars:
                password2hash = c1 + c2 + c3 + c4
                hashresult = hashlib.md5(password2hash).digest()
                sha1 = hashlib.sha1(hashresult)
                sha224 = hashlib.sha224(sha1.digest())
                for i in range(0, 10):
                    sha1 = hashlib.sha1(sha224.digest())
                    sha224 = hashlib.sha224(sha1.digest())
                output = sha224.hexdigest()
                if output == "9ee2275f8699c3146b65fabc390d83df5657a96c39ab58933f82d39b":
                    print("idek{", password2hash.decode(), "}", sep="")
                    #idek{WDOb}
                    exit()

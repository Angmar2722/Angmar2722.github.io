import binascii
import hashlib
import sys
from Crypto.Cipher import AES
import textwrap
from pwn import xor

key = b'*XhN2*8d%8Slp3*v'
key_len = len(key)

possibleChars = list(chr(i) for i in range(32, 127))
possibleKeys = []

for i in range(32, 127):
    for j in range(32, 127):
        for k in range(32, 127):
            possibleKey = chr(i) + 'XhN2' + chr(j) + '8d%8Slp3' + chr(k) + 'v'
            possibleKeys.append(possibleKey.encode())

assert len(possibleKeys) == pow(95, 3)

c = 0

for possibleKey in possibleKeys:

    h = hashlib.sha256(possibleKey).hexdigest()
    hidden = binascii.unhexlify(h)[:10]
    message = b'CBC (Cipher Blocker Chaining) is an advanced form of block cipher encryption' + hidden

    def pad(message):
        padding = bytes((key_len - len(message) % key_len) * chr(key_len - len(message) % key_len), encoding='utf-8')
        return message + padding

    messageBlocks = textwrap.wrap(pad(message).hex(), 32)[::-1]
    messageBlocks = [bytes.fromhex(block) for block in messageBlocks]

    ct = '9**********b4381646*****01********************8b9***0485******************************0**ab3a*cc5e**********18a********5383e7f**************1b3*******9f43fd66341f3ef3fab2bbfc838b9ef71867c3bcbb'
    cipherBlocks = textwrap.wrap(ct, 32)[::-1]

    for i in range(len(cipherBlocks)-1):
        cipher = AES.new(possibleKey, AES.MODE_ECB)
        decrypted = cipher.decrypt( bytes.fromhex(cipherBlocks[i]) )
        nextCipherBlock = xor(decrypted, messageBlocks[i])
        cipherBlocks[i+1] = nextCipherBlock.hex()

    cipher = AES.new(possibleKey, AES.MODE_ECB)
    decrypted = cipher.decrypt( bytes.fromhex(cipherBlocks[-1]) )
    IV = xor(messageBlocks[-1], decrypted)

    c += 1
    if(c%10000 == 0):print(c)

    try:
        if IV.decode().isascii():
            print(f"recovered iv is {IV}, key count was {c}")
    except UnicodeDecodeError:
        continue

#recovered iv is b'Y0U_D3CrYP73D_17', key count was 144543
#Flag : TMUCTF{Y0U_D3CrYP73D_17}
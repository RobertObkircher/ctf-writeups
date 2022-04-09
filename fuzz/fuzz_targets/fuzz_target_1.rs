#![no_main]

use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tinebpf::main::{BpfInstT, MAXBPFINST};

#[derive(Debug)]
struct FuzzInput {
    instructions: Vec<BpfInstT>
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> libfuzzer_sys::arbitrary::Result<Self> {
        let len = u8::arbitrary(u)? % MAXBPFINST as u8;
        let mut instructions = Vec::with_capacity(len.into());
        for i in 0..len {
            instructions.push(BpfInstT::arbitrary(u)?);
        }
        Ok(FuzzInput{instructions})
    }
}

fuzz_target!(|data: FuzzInput| {
    // tinebpf::main::run(data);
    // fuzzed code goes here
});

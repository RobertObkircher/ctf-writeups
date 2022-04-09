
use arbitrary::{Arbitrary, Unstructured};
use main::{BpfInstT, MAXBPFINST};

pub mod main;

#[derive(Debug)]
pub struct FuzzInput {
    pub instructions: Vec<BpfInstT>
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u8::arbitrary(u)? % MAXBPFINST as u8;
        let mut instructions = Vec::with_capacity(len.into());
        for _ in 0..len {
            instructions.push(BpfInstT::arbitrary(u)?);
        }
        Ok(FuzzInput{instructions})
    }
}

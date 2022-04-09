#![no_main]

use libfuzzer_sys::fuzz_target;
use tinebpf::FuzzInput;

fuzz_target!(|data: FuzzInput| {
    tinebpf::main::run(&data.instructions);
});

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: tinebpf::main::FuzzInput| {
    tinebpf::main::fuzz(data.instructions);
});

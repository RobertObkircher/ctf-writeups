use afl::fuzz;
use tinebpf::FuzzInput;

fn main() {
    fuzz!(|data: FuzzInput| {
        tinebpf::main::run(&data.instructions);
    });
}

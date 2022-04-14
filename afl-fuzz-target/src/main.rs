use afl::fuzz;

fn main() {
    fuzz!(|data: tinebpf::main::FuzzInput| {
        tinebpf::main::fuzz(data.instructions);
    });
}

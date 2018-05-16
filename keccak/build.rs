extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/keccak-tiny-unrolled.c")
        .compile("libtinykeccak.a");
}

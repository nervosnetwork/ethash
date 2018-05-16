extern crate cc;

fn main() {
    cc::Build::new()
        .flag_if_supported("-std=c99")
        .file("src/keccak-tiny-unrolled.c")
        .compile("libtinykeccak.a");
}

#[allow(dead_code)]
#[path = "src/cli.rs"]
mod cli;

use clap::CommandFactory;
use clap_mangen::Man;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = Path::new("man");
    if !out_dir.exists() {
        fs::create_dir_all(out_dir).expect("Failed to create man directory");
    }

    let cmd = cli::Cli::command();
    let man = Man::new(cmd);

    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer).expect("Failed to render man page");

    fs::write(out_dir.join("cbc.1"), buffer).expect("Failed to write cbc.1");
}

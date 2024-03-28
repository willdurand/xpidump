use clap::Parser;
use std::fs;
use xpidump::xpi;
use zip::ZipArchive;

/// A simple tool to dump information about XPI files.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input XPI file
    #[arg(short, long)]
    input: String,
}

fn main() {
    let args = Args::parse();

    let file_name = std::path::Path::new(&args.input);
    let file = fs::File::open(file_name)
        .unwrap_or_else(|_| panic!("error: failed to open '{}'", args.input));
    let mut archive =
        ZipArchive::new(file).unwrap_or_else(|_| panic!("error: failed to read '{}'", args.input));

    let xpi = xpi::XPI::new(&mut archive);
    println!("{}", xpi);
}

use clap::Parser;
use std::{fs::File, path::PathBuf};
use xpidump::XPI;
use zip::ZipArchive;

#[derive(clap::ValueEnum, Clone)]
enum Format {
    Text,
    Json,
}

/// A simple tool to dump information about XPI files.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The path to an XPI file
    file: PathBuf,
    #[clap(short, long, value_enum, default_value = "text")]
    format: Format,
}

fn main() {
    let args = Args::parse();
    let file = File::open(args.file).unwrap_or_else(|_| panic!("error: failed to open XPI file"));
    let mut archive =
        ZipArchive::new(file).unwrap_or_else(|_| panic!("error: failed to read XPI file"));

    let xpi = XPI::new(&mut archive);
    println!(
        "{}",
        match args.format {
            Format::Json => serde_json::to_string(&xpi).unwrap(),
            Format::Text => xpi.to_string(),
        }
    );
}

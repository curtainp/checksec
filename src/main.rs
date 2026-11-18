use std::fs::File;

use anyhow::{Context, Result};
use checksec::{Cli, analyze_elf, print_result};
use clap::Parser;
use goblin::elf::Elf;
use memmap2::Mmap;

fn main() -> Result<()> {
    let cli = Cli::parse();

    for path in &cli.files {
        let file =
            File::open(path).with_context(|| format!("Unable to open `{}`", path.display()))?;
        if file.metadata()?.is_file() {
            let mem_view = unsafe { Mmap::map(&file)? };
            let elf = Elf::parse(&mem_view)
                .with_context(|| format!("Failed to parse ELF file '{}'", path.display()))?;
            let result = analyze_elf(&elf, &mem_view);
            print_result(path, &result);
        }
    }
    Ok(())
}

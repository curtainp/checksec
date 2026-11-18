use clap::Parser;
use colored::Colorize;
use goblin::{
    elf::{
        Elf,
        dynamic::{
            DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_DEBUG, DT_FLAGS, DT_FLAGS_1, DT_RPATH,
            DT_RUNPATH,
        },
        header::{EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC, EM_X86_64, ET_DYN, ET_EXEC, ET_REL},
        program_header::{PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD},
    },
    elf64::section_header::SHT_NOTE,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "checksec", about = "A fast, simple checksec tool.")]
pub struct Cli {
    /// Target ELF binaries to detect
    pub files: Vec<PathBuf>,
}

#[derive(Debug, PartialEq)]
enum Relro {
    None,
    Partial,
    Full,
}

#[derive(Debug, PartialEq)]
enum Pie {
    None(u64),
    Enabled,
    Dso,
    Rel,
    Unknown,
}

#[derive(Debug, PartialEq)]
enum Nx {
    None(Option<String>),
    Enabled,
}

pub struct CheckResult {
    arch: String,
    relro: Relro,
    canary: bool,
    fortify: bool,
    nx: Nx,
    pie: Pie,
    rpath: Option<String>,
    runpath: Option<String>,
    rwx: bool,
    shstk: bool,
    ibt: bool,
    stripped: bool,
}

fn check_arch(elf: &Elf) -> String {
    let arch_name = match elf.header.e_machine {
        EM_X86_64 => "amd64",
        EM_386 => "i386",
        EM_AARCH64 => "aarch64",
        EM_ARM => "arm",
        EM_MIPS => "mips",
        EM_PPC => "powerpc",
        _ => "unknown",
    };
    let bits = if elf.is_64 { 64 } else { 32 };
    let endian = if elf.little_endian { "little" } else { "big" };
    format!("{arch_name}-{bits}-{endian}")
}

fn check_relro(elf: &Elf) -> Relro {
    let has_gnu_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);

    if !has_gnu_relro {
        return Relro::None;
    }

    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == DT_BIND_NOW {
                return Relro::Full;
            }
            if dyn_entry.d_tag == DT_FLAGS && (dyn_entry.d_val & DF_BIND_NOW) != 0 {
                return Relro::Full;
            }
            if dyn_entry.d_tag == DT_FLAGS_1 && (dyn_entry.d_val & DF_1_NOW) != 0 {
                return Relro::Full;
            }
        }
    }
    Relro::Partial
}

fn check_canary_and_fortify(elf: &Elf) -> (bool, bool) {
    let canary_syms = [
        "__stack_chk_fail",
        "__stack_chk_guard",
        "__intel_security_cookie",
    ];

    let mut has_canary = false;
    let mut has_fortify = false;

    // first check .dynsym
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if canary_syms.contains(&name) {
                has_canary = true;
            }
            if name.starts_with("__") && name.ends_with("_chk") {
                has_fortify = true;
            }
        }
    }

    // then check .symtab
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if canary_syms.contains(&name) {
                has_canary = true;
            }
            if name.starts_with("__") && name.ends_with("_chk") {
                has_fortify = true;
            }
        }
    }
    (has_canary, has_fortify)
}

fn check_nx(elf: &Elf) -> Nx {
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            if ph.p_flags & PF_X == 0 {
                return Nx::Enabled;
            } else {
                return Nx::None(None);
            }
        }
    }
    Nx::None(Some("Missing PT_GNU_STACK".into()))
}

fn get_base_address(elf: &Elf) -> u64 {
    elf.program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
        .unwrap_or(0)
}

fn check_pie(elf: &Elf) -> Pie {
    match elf.header.e_type {
        ET_EXEC => Pie::None(get_base_address(elf)),
        ET_REL => Pie::Rel,
        ET_DYN => {
            if let Some(dynamic) = &elf.dynamic {
                for entry in &dynamic.dyns {
                    if entry.d_tag == DT_DEBUG {
                        return Pie::Enabled;
                    }
                    if entry.d_tag == DT_FLAGS_1 && (entry.d_val & DF_1_PIE) != 0 {
                        return Pie::Enabled;
                    }
                }
            }
            Pie::Dso
        }
        _ => Pie::Unknown,
    }
}

fn check_rpath_runpath(elf: &Elf) -> (Option<String>, Option<String>) {
    let mut rpath = None;
    let mut runpath = None;

    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            if entry.d_tag == DT_RPATH {
                if let Some(val) = elf.dynstrtab.get_at(entry.d_val as usize) {
                    rpath = Some(val.to_string());
                }
            } else if entry.d_tag == DT_RUNPATH
                && let Some(val) = elf.dynstrtab.get_at(entry.d_val as usize)
            {
                runpath = Some(val.into());
            }
        }
    }
    (rpath, runpath)
}

fn check_rwx(elf: &Elf, nx_enabled: bool) -> bool {
    let rwx_mask = PF_R | PF_W | PF_X;
    for ph in &elf.program_headers {
        if (ph.p_flags & rwx_mask) == rwx_mask {
            return true;
        }
        if !nx_enabled && (ph.p_flags & PF_W) != 0 {
            return true;
        }
    }
    false
}

// NOTE: only for intel, which is little endianness
fn check_cet(elf: &Elf, bytes: &[u8]) -> (bool, bool) {
    let mut ibt = false;
    let mut shstk = false;

    for sh in &elf.section_headers {
        if sh.sh_type != SHT_NOTE {
            continue;
        }
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name != ".note.gnu.property" {
                continue;
            }
            let start = sh.sh_offset as usize;
            let end = start.saturating_add(sh.sh_size as usize);
            if end <= bytes.len() {
                let data = &bytes[start..end];
                for window in data.windows(12) {
                    let prop_type =
                        u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
                    let datasz = u32::from_le_bytes([window[4], window[5], window[6], window[7]]);
                    // GNU_PROPERTY_X86_FEATURE_1_AND
                    if prop_type == 0xc000_0002 && datasz == 4 {
                        let features =
                            u32::from_le_bytes([window[8], window[9], window[10], window[11]]);
                        if (features & 0x1) != 0 {
                            ibt = true;
                        }
                        if (features & 0x2) != 0 {
                            shstk = true;
                        }
                    }
                }
            }
        }
    }

    (shstk, ibt)
}

fn check_stripped(elf: &Elf) -> bool {
    elf.syms.is_empty()
}

pub fn analyze_elf(elf: &Elf, bytes: &[u8]) -> CheckResult {
    let arch = check_arch(elf);
    let relro = check_relro(elf);
    let (canary, fortify) = check_canary_and_fortify(elf);
    let nx = check_nx(elf);
    let pie = check_pie(elf);
    let (rpath, runpath) = check_rpath_runpath(elf);
    let rwx = check_rwx(elf, nx == Nx::Enabled);
    let (shstk, ibt) = check_cet(elf, bytes);
    let stripped = check_stripped(elf);

    CheckResult {
        arch,
        relro,
        canary,
        fortify,
        nx,
        pie,
        rpath,
        runpath,
        rwx,
        shstk,
        ibt,
        stripped,
    }
}

fn format_line(key: &str, value: String) -> String {
    format!("    {:<12}{}", key, value)
}

pub fn print_result(path: &Path, result: &CheckResult) {
    let abs_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    println!("[{}] '{}'", "*".blue().bold(), abs_path.display());

    println!("{}", format_line("Arch:", result.arch.clone()));

    let relro_str = match result.relro {
        Relro::Full => "Full RELRO".green().to_string(),
        Relro::Partial => "Partial RELRO".yellow().to_string(),
        Relro::None => "No RELRO".red().to_string(),
    };
    println!("{}", format_line("RELRO:", relro_str));

    let canary_str = if result.canary {
        "Canary found".green().to_string()
    } else {
        "No canary found".red().to_string()
    };
    println!("{}", format_line("Stack:", canary_str));

    let nx_str = match result.nx {
        Nx::None(Some(_)) => "NX unkown - GNU_STACK missing".yellow().to_string(),
        Nx::None(_) => "NX disabled".red().to_string(),
        _ => "NX enabled".green().to_string(),
    };
    println!("{}", format_line("NX:", nx_str));

    let pie_str = match result.pie {
        Pie::Enabled => "PIE enabled".green().to_string(),
        Pie::None(base) => format!("No PIE (0x{:x})", base).red().to_string(),
        Pie::Dso => "DSO".yellow().to_string(),
        Pie::Rel => "REL".yellow().to_string(),
        Pie::Unknown => "Unknown".red().to_string(),
    };
    println!("{}", format_line("PIE:", pie_str));

    if let Some(ref rpath) = result.rpath {
        println!(
            "{}",
            format_line("RPATH:", format!("b'{}'", rpath).red().to_string())
        );
    }
    if let Some(ref runpath) = result.runpath {
        println!(
            "{}",
            format_line("RUNPATH:", format!("b'{}'", runpath).red().to_string())
        );
    }
    if result.shstk {
        println!("{}", format_line("SHSTK:", "Enabled".green().to_string()));
    }
    if result.ibt {
        println!("{}", format_line("IBT:", "Enabled".green().to_string()));
    }
    if result.fortify {
        println!("{}", format_line("FORTIFY:", "Enabled".green().to_string()));
    }
    if result.rwx {
        println!(
            "{}",
            format_line("RWX:", "Has RWX segments".red().to_string())
        );
    }
    let stripped_str = if result.stripped {
        "Yes".to_string()
    } else {
        "No".to_string()
    };
    println!("{}", format_line("Stripped:", stripped_str));
}

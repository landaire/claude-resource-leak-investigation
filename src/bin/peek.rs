//! Dump qwords at a symbol or address: `peek <dump> <sym|0xaddr> <count>`.
use anyhow::Result;
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use resource_leak_investigation::Module;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [dump, what, n] = a.as_slice() else { anyhow::bail!("usage: peek <dump> <sym|0xaddr> <count>") };
    let parser = KernelDumpParser::new(dump)?;
    let addr = match what.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16)?,
        None => Module::load(&parser, "ntoskrnl.exe")?.sym(what)?,
    };
    let r = virt::Reader::new(&parser);
    for i in 0..n.parse::<u64>()? {
        let a = addr + i * 8;
        match r.try_read_struct::<u64>(Gva::new(a))? {
            Some(v) => println!("{a:#x}: {v:#018x}"),
            None => println!("{a:#x}: ????????????????"),
        }
    }
    Ok(())
}

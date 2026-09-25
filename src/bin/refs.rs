//! Lists qwords in a structure that point into a VA range: `refs <dump> <struct> <addr> <lo> <hi>`.
use anyhow::Result;
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use resource_leak_investigation::Module;

fn hex(s: &str) -> Result<u64> {
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [dump, ty, addr, lo, hi] = a.as_slice() else { anyhow::bail!("usage: refs <dump> <struct> <addr> <lo> <hi>") };
    let parser = KernelDumpParser::new(dump)?;
    let nt = Module::load(&parser, "ntoskrnl.exe")?;
    let r = virt::Reader::new(&parser);
    let (addr, lo, hi) = (hex(addr)?, hex(lo)?, hex(hi)?);
    let size = nt.size(ty)?;
    let mut fields = nt.fields(ty)?;
    fields.sort_by_key(|f| f.1);
    for off in (0..size).step_by(8) {
        let Some(v) = r.try_read_struct::<u64>(Gva::new(addr + off))? else { continue };
        if v >= lo && v < hi {
            let name = fields.iter().rev().find(|f| f.1 as u64 <= off).map(|f| format!("{}+{:#x}", f.0, off - f.1 as u64)).unwrap_or_default();
            println!("  +{off:#x} {name} = {v:#x}");
        }
    }
    Ok(())
}

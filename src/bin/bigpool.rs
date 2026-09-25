//! Large pool allocations from nt!PoolBigPageTable, by tag and by VA region.
use anyhow::{Context, Result};
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use resource_leak_investigation::Module;
use std::collections::HashMap;

fn main() -> Result<()> {
    let dump = std::env::args().nth(1).context("usage: bigpool <dump>")?;
    let parser = KernelDumpParser::new(&dump)?;
    let nt = Module::load(&parser, "ntoskrnl.exe")?;
    let r = virt::Reader::new(&parser);
    let table: u64 = r.read_struct(Gva::new(nt.sym("PoolBigPageTable")?))?;
    let size: u64 = r.read_struct(Gva::new(nt.sym("PoolBigPageTableSize")?))?;
    let esz = nt.size("_POOL_TRACKER_BIG_PAGES")?;
    let mut by_tag: HashMap<(u32, u16), (u64, u64)> = HashMap::new();
    for i in 0..size {
        let mut e = [0u8; 0x18];
        if r.try_read_exact(Gva::new(table + i * esz), &mut e)?.is_none() {
            continue;
        }
        let va = u64::from_le_bytes(e[0..8].try_into()?);
        if va == 0 || va & 1 != 0 {
            continue;
        }
        let tag = u32::from_le_bytes(e[8..12].try_into()?);
        let bytes = u64::from_le_bytes(e[16..24].try_into()?);
        let t = by_tag.entry((tag, (va >> 39) as u16 & 511)).or_default();
        t.0 += 1;
        t.1 += bytes;
    }
    let mut v: Vec<_> = by_tag.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1 .1));
    println!("{:<6} {:>6} {:>8} {:>12}", "tag", "pml4", "count", "MiB");
    for ((tag, idx), (n, b)) in v.iter().take(40) {
        let t: String = tag.to_le_bytes().iter().map(|&c| if c.is_ascii_graphic() { c as char } else { '.' }).collect();
        println!("{t:<6} {idx:>6} {n:>8} {:>12}", b >> 20);
    }
    Ok(())
}

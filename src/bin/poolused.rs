//! Per-tag pool usage from nt!PoolTrackTable, equivalent to `!poolused`.
use anyhow::{Context, Result};
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use resource_leak_investigation::Module;
use std::collections::HashMap;

#[derive(Default, Clone, Copy)]
struct Usage {
    np_bytes: i64,
    np_outstanding: i64,
    p_bytes: i64,
    p_outstanding: i64,
}

fn tag(k: u32) -> String {
    k.to_le_bytes().iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect()
}

fn main() -> Result<()> {
    let dump = std::env::args().nth(1).context("usage: poolused <dump>")?;
    let parser = KernelDumpParser::new(&dump)?;
    let nt = Module::load(&parser, "ntoskrnl.exe")?;
    let r = virt::Reader::new(&parser);
    let tag_tables = nt.sym("ExPoolTagTables")?;
    let size: u64 = r.read_struct(Gva::new(nt.sym("PoolTrackTableSize")?))?;
    let esz = nt.size("_POOL_TRACKER_TABLE")?;
    let mut tables = Vec::new();
    // ExPoolTagTables holds the global table followed by per-processor tables, null terminated.
    loop {
        let t: u64 = r.read_struct(Gva::new(tag_tables + tables.len() as u64 * 8))?;
        if t == 0 {
            break;
        }
        tables.push(t);
    }
    eprintln!("{} tables, size={size}", tables.len());
    let mut usage: HashMap<u32, Usage> = HashMap::new();
    let mut unreadable = 0;
    for (table, i) in tables.iter().flat_map(|&t| (0..size).map(move |i| (t, i))) {
        let mut e = [0u8; 0x38];
        if r.try_read_exact(Gva::new(table + i * esz), &mut e)?.is_none() {
            unreadable += 1;
            continue;
        }
        let q = |o: usize| i64::from_le_bytes(e[o..o + 8].try_into().unwrap());
        let key = u32::from_le_bytes(e[0..4].try_into()?);
        if key == 0 {
            continue;
        }
        let u = usage.entry(key).or_default();
        u.np_bytes += q(0x8);
        u.np_outstanding += q(0x10) - q(0x18);
        u.p_bytes += q(0x20);
        u.p_outstanding += q(0x28) - q(0x30);
    }
    eprintln!("unreadable entries: {unreadable}");
    let mut v: Vec<_> = usage.into_iter().collect();
    v.sort_by_key(|(_, u)| -(u.np_bytes + u.p_bytes));
    let (tn, tp) = v.iter().fold((0, 0), |(a, b), (_, u)| (a + u.np_bytes, b + u.p_bytes));
    println!("total nonpaged {} MiB, paged {} MiB", tn >> 20, tp >> 20);
    println!("{:<6} {:>12} {:>10} {:>12} {:>10}", "tag", "NP bytes", "NP allocs", "P bytes", "P allocs");
    for (k, u) in v.iter().take(40) {
        println!("{:<6} {:>12} {:>10} {:>12} {:>10}", tag(*k), u.np_bytes, u.np_outstanding, u.p_bytes, u.p_outstanding);
    }
    Ok(())
}

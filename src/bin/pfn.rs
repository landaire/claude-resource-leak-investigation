//! Physical memory usage by page state and use, from the PFN database.
use anyhow::{Context, Result};
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use resource_leak_investigation::Module;
use std::collections::{BTreeMap, HashMap};

const LOCATIONS: [&str; 8] = ["Zeroed", "Free", "Standby", "Modified", "ModifiedNoWrite", "Bad", "Active", "Transition"];
const REGIONS: [&str; 18] = [
    "PfnDatabase", "NonPagedPool", "PagedPool", "SystemCache", "SystemPtes", "Kasan", "UltraZero", "Cfg",
    "HyperSpace", "KernelStacks", "NonCachedMappings", "SoftWsles", "PageTables", "NotUsed",
    "SecureNonPagedPool", "KernelShadowStacks", "SystemDataViews", "SystemImages",
];

fn sign_extend(va: u64) -> u64 {
    if va & (1 << 47) != 0 { va | 0xffff_0000_0000_0000 } else { va & 0x0000_ffff_ffff_ffff }
}

fn main() -> Result<()> {
    let dump = std::env::args().nth(1).context("usage: pfn <dump>")?;
    let parser = KernelDumpParser::new(&dump)?;
    let nt = Module::load(&parser, "ntoskrnl.exe")?;
    let r = virt::Reader::new(&parser);
    let q = |a: u64| -> Result<u64> { Ok(r.read_struct::<u64>(Gva::new(a))?) };
    let pte_base = q(nt.sym("MmPteBase")?)?;
    let pfn_db = q(nt.sym("MmPfnDatabase")?)?;
    let vp = nt.sym("MiSystemPartition")? + nt.field("_MI_PARTITION", "Vp")?;
    let highest = q(vp + nt.field("_MI_VISIBLE_PARTITION", "HighestPhysicalPage")?)?;
    let vs = q(nt.sym("MiVisibleState")?)?;
    let regions_at = vs + nt.field("_MI_VISIBLE_STATE", "SystemVaRegions")?;
    let mut regions = Vec::new();
    for (i, name) in REGIONS.iter().enumerate() {
        let base = q(regions_at + i as u64 * 16)?;
        let size = q(regions_at + i as u64 * 16 + 8)?;
        if size != 0 {
            regions.push((base, base + size, *name));
        }
    }
    for (s, e, n) in &regions {
        println!("region {n:<20} {s:#x}-{e:#x}");
    }
    let modules: Vec<(u64, u64)> = parser.kernel_modules().map(|(r, _)| (u64::from(r.start), u64::from(r.end))).collect();
    let pte_end = pte_base + (1u64 << 39);
    let esz = nt.size("_MMPFN")?;

    let mut by_loc = [0u64; 8];
    let mut by_use: BTreeMap<String, u64> = BTreeMap::new();
    let mut ps_cache: HashMap<u64, bool> = HashMap::new();
    let mut missing = 0u64;
    let mut syspte_vas: Vec<(u64, u64)> = Vec::new();
    let mut pfn_va: Vec<u64> = vec![0; (highest + 1) as usize];
    const CHUNK: u64 = 4096;
    let mut buf = vec![0u8; (CHUNK * esz) as usize];
    let mut pfn = 0u64;
    while pfn <= highest {
        let n = CHUNK.min(highest + 1 - pfn);
        let b = &mut buf[..(n * esz) as usize];
        if r.try_read_exact(Gva::new(pfn_db + pfn * esz), b)?.is_none() {
            // Fall back to per-entry reads across holes in the PFN database mapping.
            for i in 0..n {
                let e = &mut b[(i * esz) as usize..((i + 1) * esz) as usize];
                if r.try_read_exact(Gva::new(pfn_db + (pfn + i) * esz), e)?.is_none() {
                    e.fill(0xff);
                }
            }
        }
        for i in 0..n {
            let e = &b[(i * esz) as usize..((i + 1) * esz) as usize];
            if e.iter().all(|&x| x == 0xff) {
                missing += 1;
                continue;
            }
            let u64at = |o: usize| u64::from_le_bytes(e[o..o + 8].try_into().unwrap());
            let loc = (e[0x22] & 7) as usize;
            let pte_addr = u64at(0x08);
            if pte_addr >= pte_base && pte_addr < pte_end && u64at(0x28) >> 63 == 0 {
                pfn_va[(pfn + i) as usize] = sign_extend(((pte_addr - pte_base) >> 3) << 12);
            }
            by_loc[loc] += 1;
            if loc <= 2 {
                continue;
            }
            let u4 = u64at(0x28);
            let pte = u64at(0x08);
            let class: String = if u4 >> 63 != 0 {
                "Shareable (prototype PTE)".into()
            } else if pte < pte_base || pte >= pte_end {
                "No PTE (driver locked, MDL, AWE)".into()
            } else {
                let va = sign_extend(((pte - pte_base) >> 3) << 12);
                if va < 0x0000_8000_0000_0000 {
                    "User private".into()
                } else if va >= pte_base && va < pte_end {
                    let large = *ps_cache.entry(pte).or_insert_with(|| {
                        r.try_read_struct::<u64>(Gva::new(pte)).ok().flatten().map_or(false, |v| v & 0x80 != 0)
                    });
                    if large { "Large page".into() } else { "Page tables".into() }
                } else if let Some((_, _, n)) = regions.iter().find(|(s, e, _)| va >= *s && va < *e) {
                    if *n == "SystemPtes" {
                        syspte_vas.push((va, pfn + i));
                    }
                    format!("Kernel {n}")
                } else if modules.iter().any(|(s, e)| va >= *s && va < *e) {
                    "Kernel SystemImages".into()
                } else {
                    format!("Kernel other (pml4 {})", (va >> 39) & 511)
                }
            };
            *by_use.entry(class).or_default() += 1;
        }
        pfn += n;
    }
    let gib = |p: u64| p as f64 * 4096.0 / (1u64 << 30) as f64;
    println!("highest pfn {highest}, unreadable pfn entries {missing}");
    println!("\nby list:");
    for (i, n) in by_loc.iter().enumerate() {
        println!("  {:<16} {:>10} pages {:>7.2} GiB", LOCATIONS[i], n, gib(*n));
    }
    let mut v: Vec<_> = by_use.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    println!("\nin use (modified, bad, active, transition) by use:");
    for (k, n) in v {
        println!("  {:<40} {:>10} pages {:>7.2} GiB", k, n, gib(n));
    }
    syspte_vas.sort();
    // Contiguous VA runs within the system PTE region.
    let mut runs: Vec<(u64, u64, u64)> = Vec::new();
    for &(va, pfn) in &syspte_vas {
        match runs.last_mut() {
            Some((start, len, _)) if *start + *len * 4096 == va => *len += 1,
            _ => runs.push((va, 1, pfn)),
        }
    }
    let mut sizes: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for (_, len, _) in &runs {
        let e = sizes.entry(*len).or_default();
        e.0 += 1;
        e.1 += len;
    }
    let mut sv: Vec<_> = sizes.into_iter().collect();
    sv.sort_by_key(|x| std::cmp::Reverse(x.1 .1));
    println!("\nsystem PTE runs: {} runs; by run length (pages: runs, total pages):", runs.len());
    for (len, (n, tot)) in sv.iter().take(15) {
        println!("  {len:>8}: {n:>8} runs {tot:>9} pages {:>7.2} GiB", gib(*tot));
    }
    if std::env::args().any(|a| a == "--refs") {
        scan_refs(&parser, &runs, &pfn_va, &regions)?;
    }
    runs.sort_by_key(|x| std::cmp::Reverse(x.1));
    println!("  largest runs:");
    for (va, len, pfn) in runs.iter().take(10) {
        println!("    {va:#x} {len} pages, first pfn {pfn:#x}");
    }
    Ok(())
}

/// Finds dumped kernel memory that holds pointers to the start of system PTE runs.
fn scan_refs(parser: &KernelDumpParser, runs: &[(u64, u64, u64)], pfn_va: &[u64], regions: &[(u64, u64, &str)]) -> Result<()> {
    use std::collections::HashSet;
    let starts: HashSet<u64> = runs.iter().map(|r| r.0).collect();
    let p = kdmp_parser::phys::Reader::new(parser);
    let mut by_region: BTreeMap<String, u64> = BTreeMap::new();
    let mut samples = Vec::new();
    let mut found: HashSet<u64> = HashSet::new();
    let mut page = [0u8; 4096];
    for (gpa, _) in parser.physmem() {
        let pa = u64::from(gpa);
        if p.read_exact(gpa, &mut page).is_err() {
            continue;
        }
        for (i, c) in page.chunks_exact(8).enumerate() {
            let v = u64::from_le_bytes(c.try_into().unwrap());
            if v & 0xfff != 0 || !starts.contains(&v) {
                continue;
            }
            found.insert(v);
            let pfn = (pa >> 12) as usize;
            let va = pfn_va.get(pfn).copied().unwrap_or(0);
            let region = if va == 0 {
                "unknown".to_string()
            } else {
                regions.iter().find(|(s, e, _)| va >= *s && va < *e).map_or("other".into(), |r| r.2.to_string())
            };
            *by_region.entry(region).or_default() += 1;
            if samples.len() < 40 {
                samples.push((va + i as u64 * 8, pa + i as u64 * 8, v));
            }
        }
    }
    println!("\nreferences to system PTE run starts: {} of {} runs referenced", found.len(), starts.len());
    for (k, v) in &by_region {
        println!("  {k:<20} {v}");
    }
    for (va, pa, v) in samples {
        println!("  ref at va {va:#x} (pa {pa:#x}) -> {v:#x}");
    }
    Ok(())
}

//! Prints the PFN entry, the PTE it references and whether the page is in the dump: `pfninfo <dump> <pfn>...`.
use anyhow::Result;
use kdmp_parser::gxa::{Gpa, Gva};
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::{phys, virt};
use resource_leak_investigation::Module;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (dump, pfns) = a.split_first().ok_or_else(|| anyhow::anyhow!("usage: pfninfo <dump> <pfn>..."))?;
    let parser = KernelDumpParser::new(dump)?;
    let nt = Module::load(&parser, "ntoskrnl.exe")?;
    let r = virt::Reader::new(&parser);
    let p = phys::Reader::new(&parser);
    let pte_base: u64 = r.read_struct(Gva::new(nt.sym("MmPteBase")?))?;
    let db: u64 = r.read_struct(Gva::new(nt.sym("MmPfnDatabase")?))?;
    for s in pfns {
        let pfn = u64::from_str_radix(s.trim_start_matches("0x"), 16)?;
        let mut e = [0u64; 6];
        for (i, v) in e.iter_mut().enumerate() {
            *v = r.read_struct(Gva::new(db + pfn * 0x30 + i as u64 * 8))?;
        }
        let pte = e[1];
        let va = (((pte.wrapping_sub(pte_base)) >> 3) << 12) | 0xffff_0000_0000_0000;
        let pte_val = r.try_read_struct::<u64>(Gva::new(pte))?;
        let mut b = [0u8; 16];
        let in_dump = p.read_exact(Gpa::new(pfn << 12), &mut b).is_ok();
        println!(
            "pfn {pfn:#x}: u1 {:#x} pte {pte:#x} (va {va:#x}) orig {:#x} u2 {:#x} u3 {:#x} u4 {:#x}; pte value {pte_val:x?}; page in dump {in_dump} {:02x?}",
            e[0], e[2], e[3], e[4], e[5], if in_dump { &b[..] } else { &[] }
        );
    }
    Ok(())
}

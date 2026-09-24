use anyhow::{Context, Result, bail};
use ezpdb::ParsedPdb;
use ezpdb::type_info::Type;
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use std::path::PathBuf;

pub struct CodeView {
    pub pdb_name: String,
    /// GUID and age formatted as the symbol server path component.
    pub signature: String,
}

pub fn read_u32(r: &virt::Reader, a: u64) -> Result<u32> {
    Ok(r.read_struct::<u32>(Gva::new(a))?)
}

pub fn codeview(r: &virt::Reader, base: u64) -> Result<CodeView> {
    let e_lfanew = read_u32(r, base + 0x3c)? as u64;
    let nt = base + e_lfanew;
    // PE32+ optional header starts at nt+0x18; data directory 6 (debug) is at +0x70+6*8.
    let dbg_rva = read_u32(r, nt + 0x18 + 0x70 + 6 * 8)? as u64;
    let dbg_size = read_u32(r, nt + 0x18 + 0x70 + 6 * 8 + 4)? as u64;
    for i in 0..dbg_size / 28 {
        let ent = base + dbg_rva + i * 28;
        if read_u32(r, ent + 12)? != 2 {
            continue;
        }
        let rva = read_u32(r, ent + 20)? as u64;
        let mut buf = [0u8; 24 + 260];
        r.read_exact(Gva::new(base + rva), &mut buf)?;
        if &buf[0..4] != b"RSDS" {
            bail!("unexpected codeview signature");
        }
        let g = &buf[4..20];
        let age = u32::from_le_bytes(buf[20..24].try_into()?);
        let d1 = u32::from_le_bytes(g[0..4].try_into()?);
        let d2 = u16::from_le_bytes(g[4..6].try_into()?);
        let d3 = u16::from_le_bytes(g[6..8].try_into()?);
        let mut signature = format!("{d1:08X}{d2:04X}{d3:04X}");
        for b in &g[8..16] {
            signature += &format!("{b:02X}");
        }
        signature += &format!("{age:X}");
        let name_end = buf[24..].iter().position(|&b| b == 0).context("pdb name")?;
        let pdb_name = String::from_utf8_lossy(&buf[24..24 + name_end]).into_owned();
        let pdb_name = pdb_name.rsplit('\\').next().context("pdb name")?.to_owned();
        return Ok(CodeView { pdb_name, signature });
    }
    bail!("no codeview entry")
}

pub fn fetch_pdb(cv: &CodeView) -> Result<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("symbols");
    let dir = root.join(&cv.pdb_name).join(&cv.signature);
    let path = dir.join(&cv.pdb_name);
    if !path.exists() {
        std::fs::create_dir_all(&dir)?;
        let url = format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
            cv.pdb_name, cv.signature, cv.pdb_name
        );
        let st = std::process::Command::new("curl").args(["-sfL", "-o"]).arg(&path).arg(&url).status()?;
        if !st.success() {
            bail!("download failed: {url}");
        }
    }
    Ok(path)
}

pub struct Module {
    pub base: u64,
    pub pdb: ParsedPdb,
}

impl Module {
    pub fn load(parser: &KernelDumpParser, name: &str) -> Result<Self> {
        let r = virt::Reader::new(parser);
        let lname = name.to_ascii_lowercase();
        let (range, _) = parser
            .kernel_modules()
            .find(|(_, n)| n.to_ascii_lowercase().ends_with(&lname))
            .with_context(|| format!("module {name} not loaded"))?;
        let base = u64::from(range.start);
        let pdb = ezpdb::parse_pdb(fetch_pdb(&codeview(&r, base)?)?, Some(base as usize))?;
        Ok(Self { base, pdb })
    }

    pub fn sym(&self, name: &str) -> Result<u64> {
        self.pdb
            .global_data
            .iter()
            .filter_map(|d| (d.name == name).then_some(d.offset).flatten())
            .chain(self.pdb.public_symbols.iter().filter_map(|s| (s.name == name).then_some(s.offset).flatten()))
            .next()
            .map(|o| o as u64)
            .with_context(|| format!("symbol {name} not found"))
    }

    /// Returns the non-forward-reference class or union named `name`.
    pub fn ty(&self, name: &str) -> Result<Type> {
        self.pdb
            .types
            .values()
            .map(|t| t.borrow().clone())
            .find(|t| match t {
                Type::Class(c) => c.name == name && !c.properties.forward_reference,
                Type::Union(u) => u.name == name && !u.properties.forward_reference,
                _ => false,
            })
            .with_context(|| format!("type {name} not found"))
    }

    pub fn fields(&self, name: &str) -> Result<Vec<(String, usize)>> {
        let fields = match self.ty(name)? {
            Type::Class(c) => c.fields,
            Type::Union(u) => u.fields,
            _ => unreachable!(),
        };
        Ok(fields
            .iter()
            .filter_map(|f| match &*f.borrow() {
                Type::Member(m) => Some((m.name.clone(), m.offset)),
                _ => None,
            })
            .collect())
    }

    pub fn field(&self, ty: &str, field: &str) -> Result<u64> {
        self.fields(ty)?
            .into_iter()
            .find(|(n, _)| n == field)
            .map(|(_, o)| o as u64)
            .with_context(|| format!("{ty}.{field} not found"))
    }

    pub fn size(&self, name: &str) -> Result<u64> {
        Ok(match self.ty(name)? {
            Type::Class(c) => c.size,
            Type::Union(u) => u.size,
            _ => unreachable!(),
        } as u64)
    }
}

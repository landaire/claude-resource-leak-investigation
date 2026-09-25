//! Symbol and type queries: `symq <dump> <module> sym|grep|type <name>`.
use anyhow::Result;
use kdmp_parser::parse::KernelDumpParser;
use resource_leak_investigation::Module;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [dump, module, cmd, name] = a.as_slice() else { anyhow::bail!("usage: symq <dump> <module> sym|grep|type|layout|enum <name>") };
    let parser = KernelDumpParser::new(dump)?;
    let m = Module::load(&parser, module)?;
    match cmd.as_str() {
        "sym" => println!("{:#x}", m.sym(name)?),
        "grep" => {
            for d in &m.pdb.global_data {
                if d.name.contains(name.as_str()) {
                    println!("data {:#x?} {}", d.offset, d.name);
                }
            }
            for s in &m.pdb.public_symbols {
                if s.name.contains(name.as_str()) {
                    println!("pub  {:#x?} {}", s.offset, s.name);
                }
            }
        }
        "layout" => layout(&m, name, 0, 0)?,
        "enum" => {
            for t in m.pdb.types.values() {
                if let ezpdb::type_info::Type::Enumeration(e) = &*t.borrow() {
                    if e.name == *name {
                        for v in &e.variants {
                            println!("  {:?} {}", v.value, v.name);
                        }
                        break;
                    }
                }
            }
        }
        "type" => {
            println!("size {:#x}", m.size(name)?);
            for (n, o) in m.fields(name)? {
                println!("  +{o:#05x} {n}");
            }
        }
        _ => anyhow::bail!("unknown command"),
    }
    Ok(())
}

/// Prints members recursively, including nested unions, structures and bitfields.
fn layout(m: &Module, name: &str, base: usize, depth: usize) -> Result<()> {
    use ezpdb::type_info::Type;
    let fields = match m.ty(name)? {
        Type::Class(c) => c.fields,
        Type::Union(u) => u.fields,
        _ => return Ok(()),
    };
    for f in &fields {
        let Type::Member(mem) = &*f.borrow() else { continue };
        let off = base + mem.offset;
        let pad = "  ".repeat(depth + 1);
        match &*mem.underlying_type.borrow() {
            Type::Bitfield(b) => println!("{pad}+{off:#05x} {} bits {}..{}", mem.name, b.position, b.position + b.len),
            Type::Class(c) => {
                println!("{pad}+{off:#05x} {} : {}", mem.name, c.name);
                if depth < 4 {
                    layout(m, &c.name, off, depth + 1)?;
                }
            }
            Type::Union(u) => {
                println!("{pad}+{off:#05x} {} : {}", mem.name, u.name);
                if depth < 4 {
                    layout(m, &u.name, off, depth + 1)?;
                }
            }
            _ => println!("{pad}+{off:#05x} {}", mem.name),
        }
    }
    Ok(())
}

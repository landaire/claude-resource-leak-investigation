//! Symbol and type queries: `symq <dump> <module> sym|grep|type <name>`.
use anyhow::Result;
use kdmp_parser::parse::KernelDumpParser;
use resource_leak_investigation::Module;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [dump, module, cmd, name] = a.as_slice() else { anyhow::bail!("usage: symq <dump> <module> sym|grep|type <name>") };
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

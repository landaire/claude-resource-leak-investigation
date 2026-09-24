//! Process list and per-process handle table analysis.
use anyhow::{Context, Result};
use kdmp_parser::gxa::Gva;
use kdmp_parser::parse::KernelDumpParser;
use kdmp_parser::virt;
use resource_leak_investigation::Module;
use std::collections::{BTreeMap, HashMap};

struct Off {
    links: u64,
    pid: u64,
    ppid: u64,
    name: u64,
    object_table: u64,
    exit_time: u64,
    create_time: u64,
    table_code: u64,
    next_handle: u64,
    type_name: u64,
    body: u64,
}

struct Proc {
    eprocess: u64,
    pid: u64,
    ppid: u64,
    name: String,
    object_table: u64,
    exited: bool,
    create_time: u64,
    pointer_count: i64,
    handle_count: i64,
}

struct Ctx<'a> {
    r: virt::Reader<'a>,
    off: Off,
    cookie: u8,
    type_table: u64,
    type_names: HashMap<u8, String>,
}

impl Ctx<'_> {
    fn q(&self, a: u64) -> Option<u64> {
        self.r.try_read_struct::<u64>(Gva::new(a)).ok().flatten()
    }

    fn unicode(&self, a: u64) -> Option<String> {
        let len = self.r.try_read_struct::<u16>(Gva::new(a)).ok().flatten()? as usize;
        let buf = self.q(a + 8)?;
        let mut b = vec![0u8; len];
        self.r.try_read_exact(Gva::new(buf), &mut b).ok().flatten()?;
        let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&w))
    }

    /// Resolves the object type name for an object header using the encoded TypeIndex.
    fn type_name(&mut self, header: u64) -> Option<String> {
        let raw = self.r.try_read_struct::<u32>(Gva::new(header + 0x18)).ok().flatten()? as u8;
        let idx = raw ^ self.cookie ^ ((header >> 8) as u8);
        if let Some(n) = self.type_names.get(&idx) {
            return Some(n.clone());
        }
        let ty = self.q(self.type_table + idx as u64 * 8)?;
        let n = self.unicode(ty + self.off.type_name)?;
        self.type_names.insert(idx, n.clone());
        Some(n)
    }

    /// Returns (handle, object body) pairs for a handle table.
    fn handles(&self, table: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let Some(code) = self.q(table + self.off.table_code) else { return out };
        let Some(next) = self.r.try_read_struct::<u32>(Gva::new(table + self.off.next_handle)).ok().flatten() else {
            return out;
        };
        let level = code & 3;
        let base = code & !7;
        let mut leaves = Vec::new();
        match level {
            0 => leaves.push(base),
            1 => (0..512).filter_map(|i| self.q(base + i * 8)).filter(|&p| p != 0).for_each(|p| leaves.push(p)),
            _ => {
                for i in 0..512 {
                    let Some(mid) = self.q(base + i * 8).filter(|&p| p != 0) else { continue };
                    (0..512).filter_map(|j| self.q(mid + j * 8)).filter(|&p| p != 0).for_each(|p| leaves.push(p));
                }
            }
        }
        for (li, leaf) in leaves.iter().enumerate() {
            let mut page = [0u8; 4096];
            if self.r.try_read_exact(Gva::new(*leaf), &mut page).ok().flatten().is_none() {
                continue;
            }
            for i in 1..256u64 {
                let handle = (li as u64 * 256 + i) * 4;
                if handle >= next as u64 {
                    break;
                }
                let low = u64::from_le_bytes(page[i as usize * 16..i as usize * 16 + 8].try_into().unwrap());
                if low == 0 {
                    continue;
                }
                // ObjectPointerBits occupies bits 20..63 and stores the header address shifted right by 4.
                let header = ((low >> 20) << 4) | 0xffff_0000_0000_0000;
                out.push((handle, header + self.off.body));
            }
        }
        out
    }
}

fn main() -> Result<()> {
    let dump = std::env::args().nth(1).context("usage: procs <dump>")?;
    let parser = KernelDumpParser::new(&dump)?;
    let nt = Module::load(&parser, "ntoskrnl.exe")?;
    let r = virt::Reader::new(&parser);
    let e = "_EPROCESS";
    let off = Off {
        links: nt.field(e, "ActiveProcessLinks")?,
        pid: nt.field(e, "UniqueProcessId")?,
        ppid: nt.field(e, "InheritedFromUniqueProcessId")?,
        name: nt.field(e, "ImageFileName")?,
        object_table: nt.field(e, "ObjectTable")?,
        exit_time: nt.field(e, "ExitTime")?,
        create_time: nt.field(e, "CreateTime")?,
        table_code: nt.field("_HANDLE_TABLE", "TableCode")?,
        next_handle: nt.field("_HANDLE_TABLE", "NextHandleNeedingPool")?,
        type_name: nt.field("_OBJECT_TYPE", "Name")?,
        body: nt.field("_OBJECT_HEADER", "Body")?,
    };
    let cookie = r.read_struct::<u32>(Gva::new(nt.sym("ObHeaderCookie")?))? as u8;
    let mut cx = Ctx { r, off, cookie, type_table: nt.sym("ObTypeIndexTable")?, type_names: HashMap::new() };

    let head = nt.sym("PsActiveProcessHead")?;
    let mut procs = Vec::new();
    let mut cur = cx.q(head).context("head")?;
    while cur != head {
        let ep = cur - cx.off.links;
        let mut nm = [0u8; 15];
        cx.r.try_read_exact(Gva::new(ep + cx.off.name), &mut nm)?;
        let name = String::from_utf8_lossy(&nm[..nm.iter().position(|&b| b == 0).unwrap_or(15)]).into_owned();
        let hdr = ep - cx.off.body;
        procs.push(Proc {
            eprocess: ep,
            pid: cx.q(ep + cx.off.pid).unwrap_or(0),
            ppid: cx.q(ep + cx.off.ppid).unwrap_or(0),
            name,
            object_table: cx.q(ep + cx.off.object_table).unwrap_or(0),
            exited: cx.q(ep + cx.off.exit_time).unwrap_or(0) != 0,
            create_time: cx.q(ep + cx.off.create_time).unwrap_or(0),
            pointer_count: cx.q(hdr).unwrap_or(0) as i64,
            handle_count: cx.q(hdr + 8).unwrap_or(0) as i64,
        });
        match cx.q(cur) {
            Some(n) => cur = n,
            None => {
                eprintln!("list broken at {cur:#x}");
                break;
            }
        }
    }
    let by_ep: HashMap<u64, usize> = procs.iter().enumerate().map(|(i, p)| (p.eprocess, i)).collect();
    let by_pid: HashMap<u64, &str> = procs.iter().filter(|p| !p.exited).map(|p| (p.pid, p.name.as_str())).collect();
    let exited: Vec<&Proc> = procs.iter().filter(|p| p.exited).collect();
    println!("processes in list: {} (exited: {})", procs.len(), exited.len());

    let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
    for p in &exited {
        *by_name.entry(&p.name).or_default() += 1;
    }
    let mut v: Vec<_> = by_name.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    println!("\nexited processes by image:");
    for (n, c) in v.iter().take(25) {
        println!("  {c:>7} {n}");
    }
    let mut by_parent: HashMap<u64, usize> = HashMap::new();
    for p in &exited {
        *by_parent.entry(p.ppid).or_default() += 1;
    }
    let mut v: Vec<_> = by_parent.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    println!("\nexited processes by parent pid:");
    for (pp, c) in v.iter().take(15) {
        println!("  {c:>7} ppid {pp:>6} {}", by_pid.get(pp).copied().unwrap_or("<exited or gone>"));
    }
    let mut v: Vec<(i64, i64)> = exited.iter().map(|p| (p.handle_count, p.pointer_count)).collect();
    v.sort();
    println!("\nexited process handle counts: min {:?} median {:?} max {:?}", v.first(), v.get(v.len() / 2), v.last());

    println!("\nhandle holders (live processes):");
    let mut rows = Vec::new();
    for p in procs.iter().filter(|p| p.object_table != 0) {
        let hs = cx.handles(p.object_table);
        let mut types: HashMap<String, usize> = HashMap::new();
        let mut exited_proc_handles = 0;
        let mut exited_targets: HashMap<String, usize> = HashMap::new();
        for (_, obj) in &hs {
            let t = cx.type_name(obj - cx.off.body).unwrap_or_else(|| "?".into());
            if t == "Process" {
                if let Some(&i) = by_ep.get(obj) {
                    if procs[i].exited {
                        exited_proc_handles += 1;
                        *exited_targets.entry(procs[i].name.clone()).or_default() += 1;
                    }
                }
            }
            *types.entry(t).or_default() += 1;
        }
        rows.push((hs.len(), exited_proc_handles, p, types, exited_targets));
    }
    rows.sort_by_key(|r| std::cmp::Reverse((r.1, r.0)));
    for (n, ex, p, types, targets) in rows.iter().take(25) {
        let mut t: Vec<_> = types.iter().collect();
        t.sort_by_key(|x| std::cmp::Reverse(*x.1));
        let t: Vec<String> = t.iter().take(6).map(|(k, v)| format!("{k}={v}")).collect();
        let mut tg: Vec<_> = targets.iter().collect();
        tg.sort_by_key(|x| std::cmp::Reverse(*x.1));
        let tg: Vec<String> = tg.iter().take(5).map(|(k, v)| format!("{k}={v}")).collect();
        println!(
            "  pid {:>6} {:<16} handles {:>7} exited-proc-handles {:>6} [{}] targets [{}]",
            p.pid, p.name, n, ex, t.join(" "), tg.join(" ")
        );
    }

    let audit = nt.field(e, "SeAuditProcessCreationInfo")?;
    let commit = nt.field(e, "CommitCharge")?;
    let ft = |t: u64| {
        let secs = (t / 10_000_000) as i64 - 11_644_473_600;
        String::from_utf8(std::process::Command::new("date").args(["-u", "-r", &secs.to_string(), "+%F %T"]).output().unwrap().stdout).unwrap().trim().to_owned()
    };
    let path = |cx: &Ctx, ep: u64| cx.q(ep + audit).and_then(|p| cx.unicode(p)).unwrap_or_default();
    println!("\nprocess details:");
    let by_pid_all: HashMap<u64, &Proc> = procs.iter().filter(|p| !p.exited).map(|p| (p.pid, p)).collect();
    for p in procs.iter().filter(|p| !p.exited && ["watchman.exe", "find.exe"].contains(&p.name.as_str())) {
        println!("  pid {} created {} commit {} pages path {}", p.pid, ft(p.create_time), cx.q(p.eprocess + commit).unwrap_or(0), path(&cx, p.eprocess));
        let mut pp = p.ppid;
        while let Some(q) = by_pid_all.get(&pp) {
            println!("    parent pid {} {} created {} path {}", q.pid, q.name, ft(q.create_time), path(&cx, q.eprocess));
            if q.ppid == q.pid { break; }
            pp = q.ppid;
        }
        if !by_pid_all.contains_key(&pp) { println!("    parent pid {pp} not present"); }
    }
    println!("\nlive processes:");
    for p in procs.iter().filter(|p| !p.exited) {
        println!("  pid {:>6} ppid {:>6} {:<16} created {} {}", p.pid, p.ppid, p.name, ft(p.create_time), path(&cx, p.eprocess));
    }
    let fname = nt.field("_FILE_OBJECT", "FileName")?;
    if let Some(w) = procs.iter().find(|p| p.name == "watchman.exe" && !p.exited) {
        println!("\nwatchman File handles:");
        let hs = cx.handles(w.object_table);
        for (h, obj) in hs {
            if cx.type_name(obj - cx.off.body).as_deref() == Some("File") {
                println!("  {h:#x} {}", cx.unicode(obj + fname).unwrap_or_default());
            }
        }
    }
    if let Some(pid) = std::env::args().nth(2).map(|s| s.parse::<u64>()).transpose()? {
        key_report(&mut cx, &nt, procs.iter().find(|p| p.pid == pid && !p.exited).context("pid")?)?;
    }
    let watchman_pid = procs.iter().find(|p| p.name == "watchman.exe" && !p.exited).map(|p| p.pid);
    let mut cmd: Vec<&Proc> = exited.iter().copied().filter(|p| Some(p.ppid) == watchman_pid).collect();
    cmd.sort_by_key(|p| p.create_time);
    if let (Some(a), Some(b)) = (cmd.first(), cmd.last()) {
        println!("\nexited children of watchman: {} from {} to {}; sample path {}", cmd.len(), ft(a.create_time), ft(b.create_time), path(&cx, a.eprocess));
        let mut hist: BTreeMap<u64, usize> = BTreeMap::new();
        for p in &cmd {
            *hist.entry(p.create_time / 10_000_000 / 3600).or_default() += 1;
        }
        for (h, c) in hist {
            println!("    {} {c}", &ft(h * 3600 * 10_000_000)[..13]);
        }
    }
    Ok(())
}

/// Summarizes the registry keys a process holds handles to.
fn key_report(cx: &mut Ctx, nt: &Module, p: &Proc) -> Result<()> {
    let kcb_off = nt.field("_CM_KEY_BODY", "KeyControlBlock")?;
    let parent = nt.field("_CM_KEY_CONTROL_BLOCK", "ParentKcb")?;
    let name_block = nt.field("_CM_KEY_CONTROL_BLOCK", "NameBlock")?;
    let kcb_name = |cx: &Ctx, kcb: u64| -> Option<String> {
        let nb = cx.q(kcb + name_block)?;
        let flags = cx.r.try_read_struct::<u32>(Gva::new(nb)).ok().flatten()?;
        let len = cx.r.try_read_struct::<u16>(Gva::new(nb + 0x18)).ok().flatten()? as usize;
        let mut b = vec![0u8; len];
        cx.r.try_read_exact(Gva::new(nb + 0x1a), &mut b).ok().flatten()?;
        Some(if flags & 1 != 0 {
            String::from_utf8_lossy(&b).into_owned()
        } else {
            String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
        })
    };
    let full = |cx: &Ctx, mut kcb: u64| {
        let mut parts = Vec::new();
        while kcb != 0 && parts.len() < 64 {
            parts.push(kcb_name(cx, kcb).unwrap_or_else(|| "?".into()));
            kcb = cx.q(kcb + parent).unwrap_or(0);
        }
        parts.reverse();
        parts.join("\\")
    };
    let mut kcbs: HashMap<u64, usize> = HashMap::new();
    let hs = cx.handles(p.object_table);
    let mut first = Vec::new();
    for (h, obj) in &hs {
        if cx.type_name(obj - cx.off.body).as_deref() != Some("Key") {
            continue;
        }
        let kcb = cx.q(obj + kcb_off).unwrap_or(0);
        *kcbs.entry(kcb).or_default() += 1;
        if first.len() < 10 {
            first.push((*h, kcb));
        }
    }
    println!("\nkey handles for pid {}: {} handles, {} distinct KCBs", p.pid, kcbs.values().sum::<usize>(), kcbs.len());
    let mut v: Vec<_> = kcbs.iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(*x.1));
    for (kcb, n) in v.iter().take(15) {
        println!("  {n:>8} {}", full(cx, **kcb));
    }
    let mut prefix: HashMap<String, usize> = HashMap::new();
    for (kcb, n) in &kcbs {
        let f = full(cx, *kcb);
        let pre: Vec<&str> = f.split('\\').take(4).collect();
        *prefix.entry(pre.join("\\")).or_default() += n;
    }
    let mut v: Vec<_> = prefix.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    println!("  by prefix:");
    for (k, n) in v.iter().take(15) {
        println!("  {n:>8} {k}");
    }
    for (h, kcb) in first {
        println!("  first handles: {h:#x} {}", full(cx, kcb));
    }
    Ok(())
}

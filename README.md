# Kernel memory leak analysis

Analysis of `live-kernel-20260924-160548.dmp`: Windows 11 build 26200,
32 processors, live kernel dump taken approximately 42 hours after boot.

## Summary

Two user-mode processes leak kernel memory through unclosed handles.

| Source | Objects held | Physical | Commit | Released when |
|---|---|---|---|---|
| `watchman.exe` (pid 2428) | 71,197 exited `cmd.exe` processes, 71,736 events | 4.9 GiB | 5.3 GiB | watchman exits |
| `find.exe` (pid 272800), Git for Windows | 1,592,853 key handles | 0.46 GiB | 0.46 GiB | find exits |

The watchman leak persists and grows while watchman runs. The find leak
grows only while the process runs.

System state at dump time: 64 GiB physical memory, 17.6 GiB available,
63.3 GiB committed of a 67.1 GiB limit. Pool: nonpaged 2.0 GiB, paged
2.4 GiB. Private commit of live processes: 35.6 GiB.

This memory does not appear in the Task Manager process memory columns,
because it is kernel memory. It is included in Performance > Memory "In
use" and "Committed". The Details tab columns Handles, Paged pool, and NP
pool identify the processes that hold the handles.

## Physical memory by use

From the PFN database (`pfn`). "Task Manager" refers to where the memory
is visible.

| Use | GiB | Mode | Task Manager |
|---|---|---|---|
| Standby | 17.3 | | Available (Cached) |
| Free and zeroed | 1.1 | | Available |
| Process private | 15.1 | User | Processes tab, Memory column (private working set) |
| of which MemCompression | 3.7 | User | Performance tab, Compressed |
| Shareable (mapped files, shared sections) | 5.1 | User, mostly | Not shown |
| System PTE mappings | 12.7 | Kernel | Not shown |
| Paged pool | 3.4 | Kernel | Performance tab |
| Page tables | 2.6 | Kernel | Not shown |
| Hyperspace (per-process working set lists) | 2.2 | Kernel | Not shown |
| No PTE (driver locked, MDL, AWE) | 2.0 | Kernel | Not shown |
| Nonpaged pool | 1.4 | Kernel | Performance tab |
| Driver images, kernel stacks, PFN database | 0.4 | Kernel | Not shown |

In use: approximately 44.7 GiB (user 20.2, kernel 24.6). The Processes tab
shows approximately 11.2 GiB (private working sets, excluding
MemCompression). The sum of private working sets from `procs` (14.9 GiB)
agrees with the PFN count (15.1 GiB).

Kernel memory attributed to the findings below: watchman exited
processes 4.9 GiB (hyperspace, page tables, pool), find.exe 0.44 GiB
(paged pool).

The 12.7 GiB of system PTE mappings is not attributed. The pages are
pageable read/write memory in the system PTE region. The live dump does
not include their contents, and no pool tag or structure in the dump
references them. To identify the owner, either compare Task Manager "In
use" and RAMMap "System PTE" before and after `watchman shutdown-server`,
or set `TrackPtes` (DWORD 1) under
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`,
restart, and use `!sysptes 4` in WinDbg.

## Finding 1: watchman does not close child process handles

`watchman.exe` v2025.02.24.00 (Chocolatey package) runs each child as
`cmd.exe /c "..."`. The Windows `waitpid` emulation in
`watchman/portability/PosixSpawn.cpp` removes the process handle from
`child_procs` without calling `CloseHandle`:

```cpp
case WAIT_OBJECT_0: {
  DWORD exitCode = 0;
  GetExitCodeProcess(h, &exitCode);
  *status = int(exitCode);
  child_procs.wlock()->erase(pid);   // h is not closed
  return pid;
}
case WAIT_ABANDONED_0:
  *status = 0;
  child_procs.wlock()->erase(pid);   // h is not closed
  return pid;
```

Each child therefore remains in memory as an exited process until
watchman exits. The thread handle is closed after `CreateProcess`, which
is consistent with the dump: 71,198 process handles and 115 thread
handles. The defect is present on upstream `main` as of 2026-09-24
(351e995a).

Data from the dump:

- 71,703 process objects exist; 71,268 have exited. 71,197 of the exited
  processes are `cmd.exe` with watchman as parent.
- Children were created from 2026-09-23 05:30 to 2026-09-24 23:05 UTC at
  2,000 to 4,900 per active hour.
- watchman watches approximately 20 repositories under `C:\Users\lander\dev`.

Cost of each exited process:

| Item | Pages | Total for 71,268 exited processes |
|---|---|---|
| PML4 page | 1 | 278 MiB |
| Per-process kernel region (PML4 index 275: working set list and hyperspace) | about 15 | 4.2 GiB |
| Pool (`Proc`, `MiP2`, `Toke`, other) | about 2 | about 0.5 GiB |
| Commit charge (`EPROCESS.CommitCharge`, 19 pages for 58,430 processes) | 19 | 5.3 GiB |

The user address space of each exited process is released: no user page
tables remain. The per-process kernel pages are released only when the
process object is deleted. The page table walk (1,145,586 pages) agrees
with the sum of `Vm.WorkingSetSize` (1,145,588 pages).

At the average rate in this dump (1,700 processes per hour) the leak is
approximately 2.8 GiB of physical memory per day. At the highest hourly
rate (4,900) it is approximately 8 GiB per day.

The command that watchman runs is not recoverable from a kernel dump,
because the command line is stored in user memory. There are two
candidates: a trigger (for example jj `fsmonitor.watchman.register-snapshot-trigger`)
or `git` invoked for source control aware queries. Check with
`watchman trigger-list <root>` or `%LOCALAPPDATA%\watchman\log`.

Fix: call `CloseHandle(h)` before each `erase(pid)`.

## Finding 2: Git for Windows find leaks registry handles

`C:\Program Files\Git\usr\bin\find.exe` was started at 2026-09-24 22:25:54
UTC in the same second as a `bash.exe` process tree under `claude.exe`.
Its parent had exited. It was still running 40 minutes later.

1,592,853 of its handles refer to one key, `\REGISTRY\USER\<SID>_Classes`.
This corresponds to msys2-runtime issue 369: enumerating
`/proc/registry/HKEY_CLASSES_ROOT` leaks one key handle for each key.

Cause, in `winsup/cygwin/fhandler/registry.cc`: `open_key` resolves the
first path component with `fetch_hkey`. For `HKEY_CLASSES_ROOT`,
`fetch_hkey` returns a real handle from `RegOpenUserClassesRoot`, but
`open_key` leaves `parentOpened` false, so the handle is not closed after
the next component is opened. Each `stat`, `open`, or `opendir` below
`HKEY_CLASSES_ROOT` leaks one handle. `HKEY_CURRENT_USER`
(`RegOpenCurrentUser`) and `HKEY_CURRENT_CONFIG` have the same defect.

The process is not blocked. Its main thread is running in
`NtEnumerateKey`. In 2,394 seconds of elapsed time it used 2,126 seconds
of kernel time and 215 seconds of user time. The other three threads are
the Cygwin signal thread and two thread pool workers, all waiting. A
`find /` enumerates `HKEY_CLASSES_ROOT` three times (`registry`,
`registry32`, `registry64`) and takes hours to complete.

The process does not stop when its parent exits. Windows does not
terminate child processes when the parent exits, and the process is not
in a job object. `SIGPIPE` does not occur because `find -name` writes
only when a name matches.

Observed rate: approximately 40,000 handles, or 11 MB, per minute for
each process. A process that runs for 24 hours holds approximately 15 GB.
When the Bash tool times out, it stops `bash` but not `find`, so
several of these processes can run at the same time.

Mitigation: stop the processes, and do not run `find /` under Git Bash.
Use `-path /proc -prune` or restrict the start directory.

## Not analyzed

- Pool tags `File` (373 MB, 932,521 objects), `FMfn` (402 MB), `MmSt`
  (238 MB), and `NtfF` (184 MB). No process holds a large number of
  handles to these objects.
- Approximately 16 GiB of commit that is not process private commit,
  pool, or shared commit. This probably includes the 12.7 GiB of system
  PTE mappings.

## Tools

The programs use the `kdmp-parser` crate (crates.io 0.8.2) to read the
dump and `ezpdb` to read symbols. Symbols are downloaded from
`msdl.microsoft.com` to `symbols/`. Build with `cargo build --release`.

| Program | Function |
|---|---|
| `poolused <dump>` | Per-tag pool usage from `nt!ExPoolTagTables`, summed over the global and per-processor tables. |
| `procs <dump> [pid]` | Process list, exited processes by image and parent, handle counts by object type for each live process, handles to exited processes, private commit, page tables and working sets of exited processes. With `pid`, the registry keys and threads of that process. |
| `pfn <dump> [--refs]` | Physical pages by list and by use. With `--refs`, searches dumped memory for pointers to system PTE mappings. |
| `bigpool <dump>` | Large pool allocations from `nt!PoolBigPageTable` by tag. |
| `pfninfo <dump> <pfn>...` | PFN entry, referenced PTE, and whether the page is in the dump. |
| `refs <dump> <struct> <addr> <lo> <hi>` | Members of a structure that point into an address range. |
| `symq <dump> <module> sym\|grep\|type\|layout\|enum <name>` | Symbol address, symbol search, structure layout (with bitfields), or enumeration values. |
| `peek <dump> <symbol\|0xaddr> <count>` | Read 64-bit values. |

`procs` uses BSD `date -r` to format timestamps. It runs on macOS.

## Reproduction

### Analysis

```sh
cargo build --release
./target/release/poolused <dump>
./target/release/procs <dump> > out-procs.txt
./target/release/procs <dump> <find.exe pid> | sed -n '/key handles for/,$p'
./target/release/pfn <dump>
```

Expected results: `poolused` lists `Proc` with approximately 71,700
outstanding allocations and `Key` with approximately 1.6 million.
`procs` lists `watchman.exe` first under handle holders, with
approximately 71,000 handles to exited processes, and reports 5,312 MiB
of private commit and 1,074,312 private kernel pages for exited
processes. `pfn` reports 11,523,644 active pages, of which 3,327,672 are
in the system PTE region.

System memory counters are in `nt!MiSystemPartition` at offset `0x4840`
(`_MI_VISIBLE_PARTITION`), for example:

```sh
./target/release/symq <dump> ntoskrnl.exe type _MI_VISIBLE_PARTITION
./target/release/peek <dump> 0x<MiSystemPartition + 0x4840 + 0x300> 1   # TotalCommittedPages
```

### watchman leak (Windows, PowerShell)

```powershell
mkdir C:\tmp\wm-leak
watchman watch C:\tmp\wm-leak
watchman -- trigger C:\tmp\wm-leak leak '*' -- cmd /c exit 0
(Get-Process watchman).HandleCount
1..500 | % { Set-Content C:\tmp\wm-leak\f.txt $_; Start-Sleep -Milliseconds 100 }
(Get-Process watchman).HandleCount
```

The handle count increases by approximately one process handle and one event
handle for each trigger run. `watchman shutdown-server` releases the
handles.

### find leak (Windows, Git Bash)

```sh
find /proc/registry/HKEY_CLASSES_ROOT > /dev/null 2>&1 &
sleep 30
powershell -c "(Get-Process find).HandleCount"
sleep 30
powershell -c "(Get-Process find).HandleCount"
kill %1
```

The handle count increases continuously. For comparison,
`find /proc/registry/HKEY_LOCAL_MACHINE/SOFTWARE/Classes` enumerates the
same keys and does not leak.

The Windows reproduction steps have not been run on this machine.

## References

- https://github.com/facebook/watchman/blob/main/watchman/portability/PosixSpawn.cpp
- https://github.com/msys2/msys2-runtime/issues/369
- https://github.com/msys2/msys2-runtime/blob/master/winsup/cygwin/fhandler/registry.cc

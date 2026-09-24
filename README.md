# Kernel memory leak analysis

Analysis of `live-kernel-20260924-160548.dmp`: Windows 11 build 26200,
32 processors, live kernel dump taken approximately 42 hours after boot.

## Summary

Two user-mode processes leak kernel objects through unclosed handles.

| Source | Objects held | Pool tags | Approximate size |
|---|---|---|---|
| `watchman.exe` (pid 2428) | 71,197 exited `cmd.exe` processes, 71,736 events | `Proc`, `MiP2`, `Toke` | 0.5 GB and more |
| `find.exe` (pid 272800), Git for Windows | 1,592,853 key handles | `Key` | 438 MB |

Pool totals at dump time: nonpaged 2.0 GB, paged 2.4 GB.

This memory does not appear in the Task Manager process memory columns,
because the objects are allocated from kernel pool. It appears in
Performance > Memory (paged and nonpaged pool, committed) and in the
Details tab columns Handles, Paged pool, and NP pool.

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
`/proc/registry/HKEY_CLASSES_ROOT` leaks one key handle for each key. A
`find /` enters `/proc/registry` and does not finish.

Observed rate: approximately 40,000 handles, or 11 MB, per minute for
each process. A process that runs for 24 hours holds approximately 15 GB.
When the Bash tool times out, it stops `bash` but not `find`, so
several of these processes can accumulate.

Mitigation: stop the processes, and do not run `find /` under Git Bash.
Use `-path /proc -prune` or restrict the start directory.

## Other large tags

`File` (373 MB, 932,521 objects), `FMfn` (402 MB), `MmSt` (238 MB), and
`NtfF` (184 MB) are also large. No process holds a large number of handles
to these objects. They were not analyzed further.

## Tools

The programs use the `kdmp-parser` crate (crates.io 0.8.2) to read the
dump and `ezpdb` to read symbols. Symbols are downloaded from
`msdl.microsoft.com` to `symbols/`. Build with `cargo build --release`.

| Program | Function |
|---|---|
| `poolused <dump>` | Per-tag pool usage from `nt!ExPoolTagTables`, summed over the global and per-processor tables. |
| `procs <dump> [pid]` | Process list, exited processes by image and parent, handle counts by object type for each live process, handles to exited processes. With `pid`, the registry keys that process holds. |
| `symq <dump> <module> sym\|grep\|type <name>` | Symbol address, symbol search, or structure layout. |
| `peek <dump> <symbol\|0xaddr> <count>` | Read 64-bit values. |

`procs` uses BSD `date -r` to format timestamps. It runs on macOS.

## Reproduction

### Analysis

```sh
cargo build --release
./target/release/poolused <dump>
./target/release/procs <dump> > out-procs.txt
./target/release/procs <dump> <find.exe pid> | sed -n '/key handles for/,$p'
```

Expected results: `poolused` lists `Proc` with approximately 71,700
outstanding allocations and `Key` with approximately 1.6 million.
`procs` lists `watchman.exe` first under handle holders, with
approximately 71,000 handles to exited processes.

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

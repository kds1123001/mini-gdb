# mini-gdb

A small debugger for x86-64 Linux, written in C on top of `ptrace(2)`. It reads ELF64 files by hand, sets software breakpoints, and uses the CPU's debug registers for hardware watchpoints.

It does not use `libelf`, `libbfd`, `libunwind`, or `capstone`. It only makes raw `PTRACE_*` calls and walks the ELF section headers itself. It is a learning project, not a replacement for gdb. It knows nothing about source code, only function names and raw addresses.

## Build

```
make
make test-target
```

`make test-target` builds a small program to debug.

You need x86-64 Linux and gcc. To trace a process you also need `CAP_SYS_PTRACE`, or the same user id as the target plus a permissive `yama/ptrace_scope`.

## Usage

```
./minigdb [path-to-binary]
mini-gdb> load <path to the test binary>
mini-gdb> break compute
mini-gdb> run
mini-gdb> cont
mini-gdb> regs
mini-gdb> watch 0x404034 write 4
mini-gdb> step
mini-gdb> quit
```

### Commands

| Command | What it does |
| --- | --- |
| `load <path>` | Parses the ELF64 headers and the symbol tables (symtab and dynsym). |
| `run [args]` | Forks and execs the target under `PTRACE_TRACEME`, then applies any pending breakpoints. |
| `attach <pid>` | Attaches to a running process with `PTRACE_ATTACH`. |
| `detach` | Detaches with `PTRACE_DETACH`. |
| `break <sym\|0xaddr>` | Sets a software breakpoint by patching in `INT3`. It can be set before `run` for PIE and static binaries. |
| `watch <addr> [exec\|write\|rw] [len]` | Sets a hardware watchpoint in DR0 to DR3. The target must already be running. |
| `cont` or `c` | Resumes. If the target is stopped on a breakpoint, it steps off it first. |
| `step` or `s` | Executes one instruction with `PTRACE_SINGLESTEP`. |
| `regs` | Prints the general-purpose registers, plus rip, rsp, rbp, and eflags. |
| `mem <addr> [len]` | Hex dump of target memory, read with `PTRACE_PEEKTEXT`. |
| `syms` | Lists the function symbols (`STT_FUNC`) of the loaded ELF. |
| `bplist`, `wplist` | Lists active breakpoints and watchpoints. |
| `kill` | Sends `SIGKILL` to the target. |
| `quit` or `q` | Kills the target if it is running, then exits. |

## How it works

**ELF parsing** (`elf_parser.c`). The file is memory-mapped. The code walks the section header table to find the symbol tables (`SHT_SYMTAB` and `SHT_DYNSYM`) and looks names up in the linked string table. It tells `ET_EXEC` files (fixed addresses) apart from `ET_DYN` files (PIE, where addresses are offsets from a load base).

**Load base.** For a PIE binary, the symbol addresses are offsets. The real load base comes from `/proc/<pid>/maps`, by finding the mapping whose file name matches the executable. Breakpoints set before `run` are stored as offsets. They become real addresses right after the child stops at `execve`, before it runs any of its own code.

**Software breakpoints** (`breakpoint.c`). The code reads the byte at the target address with `PTRACE_PEEKTEXT` and saves it. Then it writes the word back with the low byte replaced by `0xCC` using `PTRACE_POKETEXT`. When a `SIGTRAP` arrives, the CPU has already moved past the one-byte `INT3`, so the code checks `rip - 1` against the breakpoint table. To resume from a breakpoint (`bp_step_over`), it puts the original byte back, rewinds `rip`, single-steps the real instruction, writes `0xCC` again, and then continues.

**Hardware watchpoints** (`dbgregs.c`). The debug registers are read and written with `PTRACE_PEEKUSER` and `PTRACE_POKEUSER` at `offsetof(struct user, u_debugreg[n])`. DR0 to DR3 each hold one address. DR7 holds the enable bit, the access type (00 execute, 01 write, 11 read or write), and the length (00, 01, 11, 10 for 1, 2, 4, 8 bytes) for each slot. After a trap, DR6 shows which slot fired. Nothing in the target's memory is patched and nothing has to be single-stepped. Hardware watchpoints can also catch reads, which software breakpoints cannot.

**Single-stepping.** `step` is one `PTRACE_SINGLESTEP` call per instruction, using the CPU's trap flag.

## What I ran

I tried it on `target.c` built both with `-no-pie` and with `-pie`, on x86-64 Linux 6.18:

- Symbol lookup and `syms` on both kinds of binary.
- A software breakpoint hit and resumed over 5 loop iterations. `rdi` showed the loop counter each time, and the process exited cleanly after the last one.
- A breakpoint set before `run` on a PIE binary, which was moved to the right address using the load base from `/proc/<pid>/maps`.
- A DR0 write watchpoint on a global variable. It fired on each write, with the expected `rax` at the trap.
- `attach` and `detach` against the program I launched.

These were manual sessions. There is no automated test in the repo yet.

## Limitations

- **No DWARF.** There is no line or variable information. You can break on function names and raw addresses only. There is no `break file.c:42`, no source listing, and no way to inspect local variables.
- **One thread only.** Only the main thread is traced. Multi-threaded programs, and telling which thread hit which breakpoint, are not handled.
- **Watchpoint rules.** The address of a hardware watchpoint has to be aligned to its length, so a 4-byte watch needs an address that is a multiple of 4. Use length 1 for `exec` watchpoints. The 8-byte length (LEN field `10`) is written as-is, and the kernel decides whether to accept it.
- **Load base lookup uses the file name.** It could pick the wrong mapping if two mapped files share a name.
- **No disassembler.** `mem` prints raw bytes and does not decode instructions.
- **No stack unwinder.** There is no `backtrace` command. Walking `rbp` would not work on code built with `-fomit-frame-pointer` anyway.
- **No breakpoints in shared libraries.** Breakpoints are installed right after `execve`, which is safe for addresses in the main binary. Code in libraries loaded later would need a way to catch the dynamic linker's mappings, and that isn't built.
- **Signals are not passed through.** `cont` and `step` always resume with signal 0. A target that handles something like `SIGSEGV` itself will not see the original signal.
- **Narrow testing.** I only tried binaries built with `gcc -O0 -g`. Optimized and stripped binaries were not tried.

## Credits

Made by kds1123001 (aka yo boi ezdomernuggetkid)

## License

MIT. See `LICENSE`.

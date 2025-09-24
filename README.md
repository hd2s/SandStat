---
# sandstat: A Process Tracing and Profiling Utility

`sandstat` is a lightweight, command-line tool implemented in C for tracing and profiling process behavior in Linux environments (x86_64). Designed for systems programmers, graduate students, and security researchers, it provides concise insights into a process's system calls, file interactions, memory usage, and runtime characteristics. By leveraging the `ptrace` system call and `/proc` filesystem, `sandstat` offers a developer-friendly alternative to verbose tools like `strace`, delivering a human-readable summary and optional JSON output for automated analysis.

Think of `sandstat` as a focused diagnostic tool for understanding process behavior in sandboxes, debugging performance bottlenecks, or auditing system interactions in research and development settings.

---

## Features

- **System Call Profiling**: Counts and ranks system calls by frequency, highlighting dominant operations.
- **File Access Monitoring**: Tracks files opened or created via `open`, `openat`, and `creat` syscalls.
- **Memory Usage Tracking**: Measures peak Resident Set Size (VmRSS) via `/proc/<pid>/status` sampling.
- **Runtime Analysis**: Reports wall-clock time using monotonic clock for accurate duration measurement.
- **Structured Output**: Generates a clean, tabular summary with optional JSON export for scripting or CI integration.
- **Verbose Debugging**: Optional real-time event logging for detailed syscall and file access inspection.

---

## Installation

`sandstat` is built for Linux x86_64 systems and requires a C compiler (e.g., `gcc`). Follow these steps to install:

```bash
git clone https://github.com/<your-username>/sandstat.git
cd sandstat
gcc -O2 -Wall -Wextra -o sandstat sandstat.c
sudo mv sandstat /usr/local/bin/
```

**Dependencies**: Standard C library and Linux headers (`sys/ptrace.h`, `sys/uio.h`, etc.). Ensure `_GNU_SOURCE` is defined for `process_vm_readv` support.

---

## Usage

Run `sandstat` with a command to trace:

```bash
sandstat [-v] [-o output.json] -- <command> [args...]
```

### Options
- `-v`: Enable verbose mode to log syscall and file access events in real-time.
- `-o <path>`: Write summary to a JSON file for post-processing.
- `--`: Separates `sandstat` options from the target command.

### Example
Trace `ls -l` and save output to `summary.json`:

```bash
sandstat -v -o summary.json -- ls -l
```

**Sample Output** (simplified, colored in terminal):
```
╔═══════════════════════════════════════════════════════════════════════╗
║ Execution Stats                                                       ║
║ Wall Time:  0.123 seconds                                             ║
║ Peak RSS:   2048 kB (2.00 MB)                                        ║
║ Exit Status: 0                                                        ║
╠═══════════════════════════════════════════════════════════════════════╣
║ Top Syscalls (Top 10)                                                 ║
║   Syscall         | Description                      | Count            ║
║   --------------  | ------------------------------   | ------           ║
║   mmap            | Maps memory region for process   | 8                ║
║   openat          | Opens file relative to directory  | 5                ║
║   fstat           | Gets file status by descriptor   | 4                ║
╠═══════════════════════════════════════════════════════════════════════╣
║ Files Opened/Created                                                  ║
║   /usr/lib/locale/locale-archive                                      ║
╚═══════════════════════════════════════════════════════════════════════╝
```

**JSON Output** (`summary.json`):
```json
{
  "wall_time_sec": 0.123456,
  "peak_rss_kb": 2048,
  "exit_status": 0,
  "syscalls": [
    {"name": "mmap", "count": 8, "desc": "Maps memory region for process"},
    {"name": "openat", "count": 5, "desc": "Opens file relative to directory"},
    {"name": "fstat", "count": 4, "desc": "Gets file status by descriptor"}
  ],
  "files": ["/usr/lib/locale/locale-archive"]
}
```

---

## Design Rationale

`sandstat` uses the `ptrace` system call to intercept and count system calls made by a child process, offering low-overhead tracing compared to kernel-level tools like eBPF. It samples `/proc/<pid>/status` for memory usage (VmRSS) and employs `process_vm_readv` to extract file paths from syscalls like `openat`. The tool prioritizes simplicity and usability, providing a concise summary that avoids the verbosity of raw `strace` output. ANSI-colored tables and JSON output cater to both human readers and automated workflows.

Key design choices:
- **Lightweight**: Minimal dependencies, single-file C implementation (~400 LOC).
- **Focused Scope**: Targets common syscalls (e.g., `mmap`, `openat`) and file operations for practical debugging.
- **Extensible**: Syscall table and output format are easily modified for custom use cases.

---

## Use Cases

- **Performance Analysis**: Identify syscall-heavy operations or memory spikes in applications.
- **Debugging**: Trace file accesses or unexpected syscalls in sandboxed environments.
- **Security Auditing**: Monitor file interactions for potential vulnerabilities (e.g., `/tmp` writes).
- **Research**: Profile system call patterns for OS or runtime studies.
- **Teaching**: Demonstrate low-level process behavior in systems programming courses.

---

## Limitations

- **Platform**: Currently x86_64 Linux only due to syscall table and ptrace specifics.
- **Syscall Coverage**: Limited to a predefined syscall table; unknown syscalls are reported as `(unknown)`.
- **Threading**: Single-thread tracing; multi-threaded processes require `PTRACE_O_TRACECLONE` support.
- **Overhead**: `ptrace` introduces moderate slowdown (~10-20x), unsuitable for high-performance tracing.

---

## Future Enhancements

- Add syscall latency tracking for bottleneck analysis.
- Support multi-threaded processes via `PTRACE_O_TRACECLONE`.
- Implement syscall argument decoding (e.g., `execve` args).
- Add CPU usage sampling from `/proc/<pid>/stat`.
- Introduce filtering (e.g., `-e trace=open,read`) like `strace`.

---

## Contributing

Contributions are welcome! Please submit issues or pull requests to the [GitHub repository](https://github.com/<your-username>/sandstat). Ideas for new features, syscall additions, or bug fixes are appreciated. For major changes, open an issue to discuss first.

---

## License

MIT License.

---

*Authored by Harsh Singh, a graduate student in Computer Science at the University of Auckland. 2025*

---

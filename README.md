# 🛡️ sandstat — A Developer-Friendly Sandbox Insight Tool

`sandstat` is a lightweight CLI tool written in C for **tracing, profiling, and understanding what a process does inside a sandbox or restricted environment**.  
It’s designed for developers, researchers, and security enthusiasts who want a quick, human-readable summary of:

- ✅ **Syscalls made** (counted and sorted by frequency)
- 📂 **Files opened/created**
- 📊 **Peak memory usage (VmRSS)**
- ⏱ **Wall-clock runtime**
- 🧾 Optional **JSON-like output** for post-processing

Think of it as `strace` + `/proc` sampling + a clean summary in one command.

---

## ✨ Features

- **Syscall counting** — See which syscalls dominate your workload.
- **File access tracking** — Lists files opened/created (`open`, `openat`, `creat`).
- **Peak memory measurement** — Samples `/proc/<pid>/status` for VmRSS.
- **Simple summary** — No 500-line traces, just a clear report.
- **JSON-ready output** — Ideal for CI pipelines or log ingestion.
- **Verbose mode** — Watch events as they happen (great for debugging).

---

## 📦 Installation

Clone and build with `gcc` (Linux only):

```bash
git clone https://github.com/hd2s/sandstat.git
cd sandstat
gcc -O2 -Wall -Wextra -o sandstat sandstat.c

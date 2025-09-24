🛠️ sandstat – Lightweight Sandbox Insight Tool

sandstat is a developer-friendly Linux CLI tool that helps you peek inside what a program is doing — which syscalls it makes, which files it touches, and how much memory it uses — without heavy tracing setups or external profilers.

Think of it as a "poor man’s strace + memory profiler" rolled into a single, easy-to-read summary.

✨ Features

🔍 Syscall profiling – counts every syscall made by your program

📂 File access logging – records paths opened/created during runtime

📊 Peak memory usage – samples /proc/<pid>/status for VmRSS

⏱ Wall-clock timing – reports runtime in seconds

📜 Summary report – human-readable console output + optional JSON file

🚀 Quick Start
1. Build 
gcc -O2 -Wall -Wextra -o sandstat sandstat.c
2.Run 
# Trace a program with verbose output
./sandstat -v -- ./your_program arg1 arg2

# Save a report to JSON
./sandstat -o ./report.json -- /bin/ls -l

# `--` is optional after the latest patch:
./sandstat /bin/pwd
3. 🖼 Example Output
==== sandstat summary ====
Wall time: 0.003 s
Peak RSS: 1220 kB (1.19 MB)
Exit status: 0

Top syscalls (count):
  openat           : 4
  fstat            : 4
  mmap             : 3
  close            : 3
  write            : 2
  brk              : 2
  (others...)

Files opened/created:
  /etc/ld.so.cache
  /lib64/libc.so.6
  /usr/lib/locale/locale-archive

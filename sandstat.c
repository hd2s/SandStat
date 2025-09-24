// sandstat.c
// Developer-focused sandbox insight tool (Linux x86_64)
// - Traces a child process via ptrace, counts syscalls,
// - Extracts file paths from open/openat/creat,
// - Samples /proc/<pid>/status for peak VmRSS,
// - Reports wall time and exit info.
//
// Build: gcc -O2 -Wall -Wextra -o sandstat sandstat.c
// Usage: ./sandstat [-v] [-o out.json] -- <command> [args...]
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef __x86_64__
#error "This implementation currently targets Linux x86_64 only."
#endif

// ---------- Small utilities ----------
static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static double now_monotonic_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int starts_with(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

// ---------- Syscall name table (x86_64 Linux subset + holes) ----------
typedef struct { long no; const char *name; } scmap;
static scmap syscall_table[] = {
    { SYS_read, "read" }, { SYS_write, "write" }, { SYS_open, "open" },
    { SYS_close, "close" }, { SYS_stat, "stat" }, { SYS_fstat, "fstat" },
    { SYS_lstat, "lstat" }, { SYS_poll, "poll" }, { SYS_lseek, "lseek" },
    { SYS_mmap, "mmap" }, { SYS_mprotect, "mprotect" }, { SYS_munmap, "munmap" },
    { SYS_brk, "brk" }, { SYS_rt_sigaction, "rt_sigaction" },
    { SYS_rt_sigprocmask, "rt_sigprocmask" }, { SYS_ioctl, "ioctl" },
    { SYS_pread64, "pread64" }, { SYS_pwrite64, "pwrite64" },
    { SYS_readv, "readv" }, { SYS_writev, "writev" },
    { SYS_access, "access" }, { SYS_pipe, "pipe" }, { SYS_select, "select" },
    { SYS_sched_yield, "sched_yield" }, { SYS_mremap, "mremap" },
    { SYS_msync, "msync" }, { SYS_mincore, "mincore" }, { SYS_madvise, "madvise" },
    { SYS_shmget, "shmget" }, { SYS_shmat, "shmat" }, { SYS_shmctl, "shmctl" },
    { SYS_dup, "dup" }, { SYS_dup2, "dup2" }, { SYS_pause, "pause" },
    { SYS_nanosleep, "nanosleep" }, { SYS_getitimer, "getitimer" },
    { SYS_alarm, "alarm" }, { SYS_setitimer, "setitimer" },
    { SYS_getpid, "getpid" }, { SYS_sendfile, "sendfile" },
    { SYS_socket, "socket" }, { SYS_connect, "connect" }, { SYS_accept, "accept" },
    { SYS_sendto, "sendto" }, { SYS_recvfrom, "recvfrom" },
    { SYS_sendmsg, "sendmsg" }, { SYS_recvmsg, "recvmsg" },
    { SYS_shutdown, "shutdown" }, { SYS_bind, "bind" }, { SYS_listen, "listen" },
    { SYS_getsockname, "getsockname" }, { SYS_getpeername, "getpeername" },
    { SYS_socketpair, "socketpair" }, { SYS_setsockopt, "setsockopt" },
    { SYS_getsockopt, "getsockopt" }, { SYS_clone, "clone" }, { SYS_fork, "fork" },
    { SYS_vfork, "vfork" }, { SYS_execve, "execve" }, { SYS_exit, "exit" },
    { SYS_wait4, "wait4" }, { SYS_kill, "kill" }, { SYS_uname, "uname" },
    { SYS_semget, "semget" }, { SYS_semop, "semop" }, { SYS_semctl, "semctl" },
    { SYS_shmdt, "shmdt" }, { SYS_msgget, "msgget" }, { SYS_msgsnd, "msgsnd" },
    { SYS_msgrcv, "msgrcv" }, { SYS_msgctl, "msgctl" }, { SYS_fcntl, "fcntl" },
    { SYS_fsync, "fsync" }, { SYS_fdatasync, "fdatasync" }, { SYS_truncate, "truncate" },
    { SYS_ftruncate, "ftruncate" }, { SYS_getdents, "getdents" },
    { SYS_getcwd, "getcwd" }, { SYS_chdir, "chdir" }, { SYS_fchdir, "fchdir" },
    { SYS_rename, "rename" }, { SYS_mkdir, "mkdir" }, { SYS_rmdir, "rmdir" },
    { SYS_creat, "creat" }, { SYS_link, "link" }, { SYS_unlink, "unlink" },
    { SYS_symlink, "symlink" }, { SYS_readlink, "readlink" },
    { SYS_chmod, "chmod" }, { SYS_fchmod, "fchmod" }, { SYS_chown, "chown" },
    { SYS_lchown, "lchown" }, { SYS_umask, "umask" }, { SYS_gettimeofday, "gettimeofday" },
    { SYS_getrlimit, "getrlimit" }, { SYS_getrusage, "getrusage" },
    { SYS_sysinfo, "sysinfo" }, { SYS_times, "times" }, { SYS_ptrace, "ptrace" },
    { SYS_getuid, "getuid" }, { SYS_syslog, "syslog" }, { SYS_getgid, "getgid" },
    { SYS_setuid, "setuid" }, { SYS_setgid, "setgid" }, { SYS_geteuid, "geteuid" },
    { SYS_getegid, "getegid" }, { SYS_setpgid, "setpgid" }, { SYS_getppid, "getppid" },
    { SYS_getpgrp, "getpgrp" }, { SYS_setsid, "setsid" }, { SYS_setreuid, "setreuid" },
    { SYS_setregid, "setregid" }, { SYS_getgroups, "getgroups" },
    { SYS_setgroups, "setgroups" }, { SYS_setresuid, "setresuid" },
    { SYS_getresuid, "getresuid" }, { SYS_setresgid, "setresgid" },
    { SYS_getresgid, "getresgid" }, { SYS_openat, "openat" }, { SYS_unlinkat, "unlinkat" },
    { SYS_newfstatat, "newfstatat" }, { SYS_renameat, "renameat" },
    { SYS_linkat, "linkat" }, { SYS_symlinkat, "symlinkat" }, { SYS_readlinkat, "readlinkat" },
    { SYS_utimensat, "utimensat" }, { SYS_execveat, "execveat" },
    { SYS_prlimit64, "prlimit64" }, { SYS_statx, "statx" },
    // Additional syscalls to reduce unknowns
    { SYS_arch_prctl, "arch_prctl" }, { SYS_set_robust_list, "set_robust_list" },
    { SYS_get_robust_list, "get_robust_list" }, { SYS_futex, "futex" },
    { SYS_set_tid_address, "set_tid_address" }, { SYS_getdents64, "getdents64" },
    { SYS_clock_gettime, "clock_gettime" }, { SYS_getrandom, "getrandom" },
    { SYS_rseq, "rseq" }, { SYS_pipe2, "pipe2" }, { SYS_epoll_create, "epoll_create" },
    { SYS_epoll_ctl, "epoll_ctl" }, { SYS_epoll_wait, "epoll_wait" },
    { SYS_eventfd2, "eventfd2" }, { SYS_inotify_init1, "inotify_init1" },
    { SYS_inotify_add_watch, "inotify_add_watch" }, { SYS_inotify_rm_watch, "inotify_rm_watch" },
};
static const size_t syscall_table_len = sizeof(syscall_table)/sizeof(syscall_table[0]);

static const char* syscall_name(long no) {
    for (size_t i=0;i<syscall_table_len;i++)
        if (syscall_table[i].no == no) return syscall_table[i].name;
    return NULL;
}

// ---------- Dynamic arrays ----------
typedef struct {
    long no;
    unsigned long count;
} SysCount;

typedef struct {
    SysCount *a;
    size_t n, cap;
} SysVec;

static void sysvec_add(SysVec *v, long no) {
    for (size_t i=0;i<v->n;i++) if (v->a[i].no==no){ v->a[i].count++; return; }
    if (v->n==v->cap){ v->cap = v->cap? v->cap*2:64; v->a = (SysCount *)realloc(v->a, v->cap*sizeof(SysCount)); }
    v->a[v->n++] = (SysCount){.no=no,.count=1};
}

typedef struct {
    char **a;
    size_t n, cap;
} StrVec;

static int strvec_contains(StrVec *v, const char *s) {
    for (size_t i=0;i<v->n;i++) if (strcmp(v->a[i], s)==0) return 1;
    return 0;
}
static void strvec_add(StrVec *v, const char *s) {
    if (strvec_contains(v, s)) return;
    if (v->n==v->cap){ v->cap = v->cap? v->cap*2:64; v->a = (char **)realloc(v->a, v->cap*sizeof(char*)); }
    v->a[v->n++] = strdup(s);
}
static void strvec_free(StrVec *v){ for (size_t i=0;i<v->n;i++) free(v->a[i]); free(v->a); }

// ---------- Read child memory string ----------
static ssize_t read_child_string(pid_t pid, unsigned long addr, char *buf, size_t maxlen) {
    struct iovec local = { .iov_base = buf, .iov_len = maxlen-1 };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = maxlen-1 };
    ssize_t r = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (r <= 0) return -1;
    size_t n = (size_t)r;
    size_t i; for (i=0;i<n;i++) if (buf[i]==0) break;
    if (i==n) { if (n<maxlen) buf[n]=0; else buf[maxlen-1]=0; }
    else buf[i]=0;
    return (ssize_t)strlen(buf);
}

// ---------- Peak RSS sampler ----------
static long read_vmrss_kb(pid_t pid) {
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof(line), f)) {
        if (starts_with(line, "VmRSS:")) {
            char *p = line;
            while (*p && !isdigit((unsigned char)*p)) p++;
            kb = strtol(p, NULL, 10);
            break;
        }
    }
    fclose(f);
    return kb;
}

// ---------- Main tracer ----------
static int verbose = 0;
static const char *out_path = NULL;

static void print_summary(SysVec *sys, StrVec *files, double sec, long peak_kb, int exited, int code, int sig) {
    // ANSI color codes
    #define ANSI_RESET   "\033[0m"
    #define ANSI_BOLD    "\033[1m"
    #define ANSI_CYAN    "\033[36m"
    #define ANSI_GREEN   "\033[32m"
    #define ANSI_YELLOW  "\033[33m"
    #define ANSI_MAGENTA "\033[35m"
    #define ANSI_RED     "\033[31m"

    // Print header
    printf("\n%s╔════════════════════════════ sandstat Summary ════════════════════════════╗%s\n", ANSI_CYAN, ANSI_RESET);

    // Execution stats
    printf("%s║%s Execution Stats %s║%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_CYAN, ANSI_RESET);
    printf("%s║%s Wall Time:  %s%.3f seconds%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_GREEN, sec, ANSI_RESET);
    if (peak_kb >= 0) {
        printf("%s║%s Peak RSS:   %s%ld kB (%.2f MB)%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_GREEN, peak_kb, peak_kb/1024.0, ANSI_RESET);
    }
    if (exited) {
        printf("%s║%s Exit Status: %s%d%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_GREEN, code, ANSI_RESET);
    } else {
        printf("%s║%s Terminated by Signal: %s%d%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_RED, sig, ANSI_RESET);
    }
    printf("%s╠══════════════════════════════════════════════════════════════════════════╣%s\n", ANSI_CYAN, ANSI_RESET);

    // Syscall counts
    printf("%s║%s Top Syscalls (Top %zu)%s\n", ANSI_CYAN, ANSI_BOLD, sys->n < 20 ? sys->n : 20, ANSI_RESET);
    if (sys->n == 0) {
        printf("%s║%s   (none captured)%s\n", ANSI_CYAN, ANSI_YELLOW, ANSI_RESET);
    } else {
        // Sort syscalls by count (descending)
        for (size_t i = 0; i < sys->n; i++)
            for (size_t j = i + 1; j < sys->n; j++)
                if (sys->a[j].count > sys->a[i].count) {
                    SysCount t = sys->a[i]; sys->a[i] = sys->a[j]; sys->a[j] = t;
                }
        size_t show = sys->n < 20 ? sys->n : 20;
        for (size_t i = 0; i < show; i++) {
            const char *nm = syscall_name(sys->a[i].no);
            printf("%s║%s   %-20s : %s%lu%s\n", ANSI_CYAN, ANSI_BOLD, nm ? nm : "(unknown)", ANSI_YELLOW, sys->a[i].count, ANSI_RESET);
        }
    }
    printf("%s╠══════════════════════════════════════════════════════════════════════════╣%s\n", ANSI_CYAN, ANSI_RESET);

    // Files accessed
    printf("%s║%s Files Opened/Created%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_RESET);
    if (files->n == 0) {
        printf("%s║%s   (none captured)%s\n", ANSI_CYAN, ANSI_YELLOW, ANSI_RESET);
    } else {
        for (size_t i = 0; i < files->n; i++) {
            printf("%s║%s   %s%s%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_MAGENTA, files->a[i], ANSI_RESET);
        }
    }
    printf("%s╚══════════════════════════════════════════════════════════════════════════╝%s\n", ANSI_CYAN, ANSI_RESET);

    // JSON output
    if (out_path) {
        FILE *o = fopen(out_path, "w");
        if (!o) { perror("fopen -o"); return; }
        fprintf(o, "{\n");
        fprintf(o, "  \"wall_time_sec\": %.6f,\n", sec);
        fprintf(o, "  \"peak_rss_kb\": %ld,\n", peak_kb);
        if (exited) fprintf(o, "  \"exit_status\": %d,\n", code);
        else        fprintf(o, "  \"term_signal\": %d,\n", sig);
        fprintf(o, "  \"syscalls\": [\n");
        for (size_t i = 0; i < sys->n; i++) {
            const char *nm = syscall_name(sys->a[i].no);
            fprintf(o, "    {\"name\":\"%s\",\"count\":%lu}%s\n",
                nm ? nm : "unknown", sys->a[i].count, (i + 1 < sys->n) ? "," : "");
        }
        fprintf(o, "  ],\n  \"files\": [\n");
        for (size_t i = 0; i < files->n; i++) {
            const char *s = files->a[i];
            fputc(' ', o); fputc(' ', o); fputc(' ', o); fputc(' ', o);
            fputc('"', o);
            for (const char *p = s; *p; ++p) {
                if (*p == '\\' || *p == '"') fputc('\\', o);
                fputc(*p, o);
            }
            fputc('"', o);
            fprintf(o, "%s\n", (i + 1 < files->n) ? "," : "");
        }
        fprintf(o, "  ]\n}\n");
        fclose(o);
        if (verbose) fprintf(stderr, "[sandstat] wrote %s\n", out_path);
    }
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [-v] [-o out.json] -- <command> [args...]\n"
        "  -v            verbose (log events)\n"
        "  -o <path>     write JSON-like summary\n", argv0);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "+vo:")) != -1) {
        switch (opt) {
            case 'v': verbose = 1; break;
            case 'o': out_path = optarg; break;
            default: usage(argv[0]); return 2;
        }
    }

    int cmd_index = optind;
    if (cmd_index < argc && strcmp(argv[cmd_index], "--") == 0) cmd_index++;

    if (cmd_index >= argc) { usage(argv[0]); return 2; }

    char **cmd = &argv[cmd_index];

    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) die("ptrace(TRACEME)");
        raise(SIGSTOP);
        execvp(cmd[0], cmd);
        perror("execvp");
        _exit(127);
    }

    int status;
    if (waitpid(child, &status, 0) == -1) die("waitpid(SIGSTOP)");
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Child didn't stop as expected\n"); return 1;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
        (void*)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)) == -1)
        die("ptrace(SETOPTIONS)");

    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) die("ptrace(SYSCALL start)");

    double t0 = now_monotonic_sec();
    long peak_kb = -1;

    SysVec sc = {0};
    StrVec files = {0};

    int in_syscall = 0;
    int exited_normally = 0, exit_status_code = 0, term_sig = 0;

    while (1) {
        if (waitpid(child, &status, 0) == -1) {
            if (errno == EINTR) continue;
            die("waitpid loop");
        }

        if (WIFEXITED(status)) {
            exited_normally = 1;
            exit_status_code = WEXITSTATUS(status);
            break;
        } else if (WIFSIGNALED(status)) {
            term_sig = WTERMSIG(status);
            break;
        } else if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == (SIGTRAP | 0x80)) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) die("ptrace(GETREGS)");
                long scno = regs.orig_rax;
                if (!in_syscall) {
                    sysvec_add(&sc, scno);
                    long kb = read_vmrss_kb(child);
                    if (kb > peak_kb) peak_kb = kb;
                    if (scno == SYS_open) {
                        unsigned long p = regs.rdi;
                        char buf[4096];
                        if (read_child_string(child, p, buf, sizeof(buf)) > 0)
                            strvec_add(&files, buf), verbose && fprintf(stderr, "[open] %s\n", buf);
                    } else if (scno == SYS_creat) {
                        unsigned long p = regs.rdi;
                        char buf[4096];
                        if (read_child_string(child, p, buf, sizeof(buf)) > 0)
                            strvec_add(&files, buf), verbose && fprintf(stderr, "[creat] %s\n", buf);
                    } else if (scno == SYS_openat) {
                        unsigned long p = regs.rsi;
                        char buf[4096];
                        if (read_child_string(child, p, buf, sizeof(buf)) > 0)
                            strvec_add(&files, buf), verbose && fprintf(stderr, "[openat] %s\n", buf);
                    }
                }
                in_syscall = !in_syscall;
                if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) die("ptrace(SYSCALL cont)");
                continue;
            }
            if (sig == SIGSTOP || sig == SIGTRAP) {
                if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) die("ptrace(SYSCALL resume)");
            } else {
                if (ptrace(PTRACE_SYSCALL, child, NULL, (void*)(long)sig) == -1) die("ptrace(SYSCALL pass-sig)");
            }
        }
    }

    double t1 = now_monotonic_sec();
    print_summary(&sc, &files, t1 - t0, peak_kb, exited_normally, exit_status_code, term_sig);

    free(sc.a);
    strvec_free(&files);
    return exited_normally ? exit_status_code : 128 + term_sig;
}

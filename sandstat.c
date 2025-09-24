// sandstat.c
// Copyright (c) 2025 Harsh Singh, University of Auckland. Licensed under the MIT License.

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

#include <sys/ioctl.h>

static int use_color = 1;

static int term_width(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 40)
        return ws.ws_col;
    const char *cols = getenv("COLUMNS");
    if (cols) {
        int v = atoi(cols);
        if (v >= 40) return v;
    }
    return 100; // sensible default
}

static int num_digits_unsigned_unsigned(unsigned long v) {
    int d = 1;
    while (v >= 10) { v /= 10; d++; }
    return d;
}

/* ANSI helpers */
#define C_RESET   (use_color? "\033[0m"  : "")
#define C_BOLD    (use_color? "\033[1m"  : "")
#define C_DIM     (use_color? "\033[2m"  : "")
#define C_RED     (use_color? "\033[31m" : "")
#define C_GREEN   (use_color? "\033[32m" : "")
#define C_YELLOW  (use_color? "\033[33m" : "")
#define C_BLUE    (use_color? "\033[34m" : "")
#define C_MAGENTA (use_color? "\033[35m" : "")
#define C_CYAN    (use_color? "\033[36m" : "")

/* Safe truncate with ellipsis for a given width (>= 3). Returns bytes printed. */
static int print_fit(const char *s, int width) {
    int n = (int)strlen(s);
    if (n <= width) {
        printf("%-*s", width, s);
        return width;
    }
    if (width <= 3) {
        for (int i=0;i<width;i++) putchar('.');
        return width;
    }
    fwrite(s, 1, (size_t)(width-3), stdout);
    fputs("...", stdout);
    return width;
}

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
typedef struct { long no; const char *name; const char *desc; } scmap;
static scmap syscall_table[] = {
    { SYS_read, "read", "Reads data from file descriptor" },
    { SYS_write, "write", "Writes data to file descriptor" },
    { SYS_open, "open", "Opens file with specified flags" },
    { SYS_close, "close", "Closes an open file descriptor" },
    { SYS_stat, "stat", "Gets file status from path" },
    { SYS_fstat, "fstat", "Gets file status by descriptor" },
    { SYS_lstat, "lstat", "Gets symbolic link file status" },
    { SYS_poll, "poll", "Waits for events on descriptors" },
    { SYS_lseek, "lseek", "Repositions file offset for descriptor" },
    { SYS_mmap, "mmap", "Maps memory region for process" },
    { SYS_mprotect, "mprotect", "Sets memory protection for region" },
    { SYS_munmap, "munmap", "Unmaps memory region from process" },
    { SYS_brk, "brk", "Adjusts program break for heap" },
    { SYS_rt_sigaction, "rt_sigaction", "Sets signal handler for process" },
    { SYS_rt_sigprocmask, "rt_sigprocmask", "Modifies blocked signals for process" },
    { SYS_ioctl, "ioctl", "Controls device-specific operations" },
    { SYS_pread64, "pread64", "Reads file at specific offset" },
    { SYS_pwrite64, "pwrite64", "Writes file at specific offset" },
    { SYS_readv, "readv", "Reads into multiple buffers" },
    { SYS_writev, "writev", "Writes from multiple buffers" },
    { SYS_access, "access", "Checks file access permissions" },
    { SYS_pipe, "pipe", "Creates pipe for interprocess communication" },
    { SYS_select, "select", "Monitors multiple descriptors for events" },
    { SYS_sched_yield, "sched_yield", "Yields CPU to other processes" },
    { SYS_mremap, "mremap", "Remaps memory region size/location" },
    { SYS_msync, "msync", "Synchronizes memory with storage" },
    { SYS_mincore, "mincore", "Checks memory page residency" },
    { SYS_madvise, "madvise", "Advises kernel on memory usage" },
    { SYS_shmget, "shmget", "Allocates shared memory segment" },
    { SYS_shmat, "shmat", "Attaches shared memory to process" },
    { SYS_shmctl, "shmctl", "Controls shared memory segment" },
    { SYS_dup, "dup", "Duplicates file descriptor" },
    { SYS_dup2, "dup2", "Duplicates descriptor to specific number" },
    { SYS_pause, "pause", "Suspends process until signal" },
    { SYS_nanosleep, "nanosleep", "Sleeps for specified time" },
    { SYS_getitimer, "getitimer", "Gets interval timer value" },
    { SYS_alarm, "alarm", "Sets process alarm clock" },
    { SYS_setitimer, "setitimer", "Sets interval timer" },
    { SYS_getpid, "getpid", "Gets process ID" },
    { SYS_sendfile, "sendfile", "Transfers data between descriptors" },
    { SYS_socket, "socket", "Creates new socket" },
    { SYS_connect, "connect", "Initiates connection on socket" },
    { SYS_accept, "accept", "Accepts incoming socket connection" },
    { SYS_sendto, "sendto", "Sends data to specific address" },
    { SYS_recvfrom, "recvfrom", "Receives data from socket" },
    { SYS_sendmsg, "sendmsg", "Sends message via socket" },
    { SYS_recvmsg, "recvmsg", "Receives message via socket" },
    { SYS_shutdown, "shutdown", "Shuts down socket operations" },
    { SYS_bind, "bind", "Binds socket to address" },
    { SYS_listen, "listen", "Listens for socket connections" },
    { SYS_getsockname, "getsockname", "Gets socket's local address" },
    { SYS_getpeername, "getpeername", "Gets socket's peer address" },
    { SYS_socketpair, "socketpair", "Creates paired sockets" },
    { SYS_setsockopt, "setsockopt", "Sets socket options" },
    { SYS_getsockopt, "getsockopt", "Gets socket options" },
    { SYS_clone, "clone", "Creates new process or thread" },
    { SYS_fork, "fork", "Creates new child process" },
    { SYS_vfork, "vfork", "Creates child with shared memory" },
    { SYS_execve, "execve", "Executes new program" },
    { SYS_exit, "exit", "Terminates calling process" },
    { SYS_wait4, "wait4", "Waits for child process status" },
    { SYS_kill, "kill", "Sends signal to process" },
    { SYS_uname, "uname", "Gets system information" },
    { SYS_semget, "semget", "Creates semaphore set" },
    { SYS_semop, "semop", "Performs semaphore operations" },
    { SYS_semctl, "semctl", "Controls semaphore set" },
    { SYS_shmdt, "shmdt", "Detaches shared memory" },
    { SYS_msgget, "msgget", "Creates message queue" },
    { SYS_msgsnd, "msgsnd", "Sends message to queue" },
    { SYS_msgrcv, "msgrcv", "Receives message from queue" },
    { SYS_msgctl, "msgctl", "Controls message queue" },
    { SYS_fcntl, "fcntl", "Controls file descriptor properties" },
    { SYS_fsync, "fsync", "Synchronizes file with storage" },
    { SYS_fdatasync, "fdatasync", "Synchronizes file data" },
    { SYS_truncate, "truncate", "Truncates file to length" },
    { SYS_ftruncate, "ftruncate", "Truncates file by descriptor" },
    { SYS_getdents, "getdents", "Gets directory entries" },
    { SYS_getcwd, "getcwd", "Gets current working directory" },
    { SYS_chdir, "chdir", "Changes working directory" },
    { SYS_fchdir, "fchdir", "Changes directory by descriptor" },
    { SYS_rename, "rename", "Renames file or directory" },
    { SYS_mkdir, "mkdir", "Creates new directory" },
    { SYS_rmdir, "rmdir", "Removes empty directory" },
    { SYS_creat, "creat", "Creates new file" },
    { SYS_link, "link", "Creates hard link" },
    { SYS_unlink, "unlink", "Removes file link" },
    { SYS_symlink, "symlink", "Creates symbolic link" },
    { SYS_readlink, "readlink", "Reads symbolic link target" },
    { SYS_chmod, "chmod", "Changes file permissions" },
    { SYS_fchmod, "fchmod", "Changes permissions by descriptor" },
    { SYS_chown, "chown", "Changes file ownership" },
    { SYS_lchown, "lchown", "Changes ownership of symlink" },
    { SYS_umask, "umask", "Sets file creation mask" },
    { SYS_gettimeofday, "gettimeofday", "Gets current time" },
    { SYS_getrlimit, "getrlimit", "Gets resource limits" },
    { SYS_getrusage, "getrusage", "Gets resource usage" },
    { SYS_sysinfo, "sysinfo", "Gets system statistics" },
    { SYS_times, "times", "Gets process times" },
    { SYS_ptrace, "ptrace", "Traces process execution" },
    { SYS_getuid, "getuid", "Gets user ID" },
    { SYS_syslog, "syslog", "Logs to system log" },
    { SYS_getgid, "getgid", "Gets group ID" },
    { SYS_setuid, "setuid", "Sets user ID" },
    { SYS_setgid, "setgid", "Sets group ID" },
    { SYS_geteuid, "geteuid", "Gets effective user ID" },
    { SYS_getegid, "getegid", "Gets effective group ID" },
    { SYS_setpgid, "setpgid", "Sets process group ID" },
    { SYS_getppid, "getppid", "Gets parent process ID" },
    { SYS_getpgrp, "getpgrp", "Gets process group ID" },
    { SYS_setsid, "setsid", "Creates new session" },
    { SYS_setreuid, "setreuid", "Sets real/effective user ID" },
    { SYS_setregid, "setregid", "Sets real/effective group ID" },
    { SYS_getgroups, "getgroups", "Gets supplementary group IDs" },
    { SYS_setgroups, "setgroups", "Sets supplementary group IDs" },
    { SYS_setresuid, "setresuid", "Sets real/effective/saved user ID" },
    { SYS_getresuid, "getresuid", "Gets real/effective/saved user ID" },
    { SYS_setresgid, "setresgid", "Sets real/effective/saved group ID" },
    { SYS_getresgid, "getresgid", "Gets real/effective/saved group ID" },
    { SYS_openat, "openat", "Opens file relative to directory" },
    { SYS_unlinkat, "unlinkat", "Removes file relative to directory" },
    { SYS_newfstatat, "newfstatat", "Gets file status relative to directory" },
    { SYS_renameat, "renameat", "Renames file relative to directory" },
    { SYS_linkat, "linkat", "Creates link relative to directory" },
    { SYS_symlinkat, "symlinkat", "Creates symlink relative to directory" },
    { SYS_readlinkat, "readlinkat", "Reads symlink relative to directory" },
    { SYS_utimensat, "utimensat", "Sets file timestamps" },
    { SYS_execveat, "execveat", "Executes program relative to directory" },
    { SYS_prlimit64, "prlimit64", "Sets/gets process resource limits" },
    { SYS_statx, "statx", "Gets extended file status" },
    // Additional syscalls from previous suggestion
    { SYS_arch_prctl, "arch_prctl", "Sets architecture-specific thread state" },
    { SYS_set_robust_list, "set_robust_list", "Sets robust futex list" },
    { SYS_get_robust_list, "get_robust_list", "Gets robust futex list" },
    { SYS_futex, "futex", "Manages fast user-space mutexes" },
    { SYS_set_tid_address, "set_tid_address", "Sets thread ID address" },
    { SYS_getdents64, "getdents64", "Gets directory entries (64-bit)" },
    { SYS_clock_gettime, "clock_gettime", "Gets current time of clock" },
    { SYS_getrandom, "getrandom", "Generates random bytes" },
    { SYS_rseq, "rseq", "Implements restartable sequences" },
    { SYS_pipe2, "pipe2", "Creates pipe with flags" },
    { SYS_epoll_create, "epoll_create", "Creates epoll instance" },
    { SYS_epoll_ctl, "epoll_ctl", "Controls epoll instance" },
    { SYS_epoll_wait, "epoll_wait", "Waits for epoll events" },
    { SYS_eventfd2, "eventfd2", "Creates event file descriptor" },
    { SYS_inotify_init1, "inotify_init1", "Initializes inotify instance" },
    { SYS_inotify_add_watch, "inotify_add_watch", "Adds watch to inotify" },
    { SYS_inotify_rm_watch, "inotify_rm_watch", "Removes watch from inotify" },
};
static const size_t syscall_table_len = sizeof(syscall_table)/sizeof(syscall_table[0]);

static const char* syscall_name(long no) {
    for (size_t i=0;i<syscall_table_len;i++)
        if (syscall_table[i].no == no) return syscall_table[i].name;
    return NULL;
}

static const char* syscall_desc(long no) {
    for (size_t i=0;i<syscall_table_len;i++)
        if (syscall_table[i].no == no) return syscall_table[i].desc;
    return "Unknown system call function";
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
/* Sunglasses ASCII art — clean, rectangular, cool 😎 */
static const char *side_art[] = {
    "      ________     ________      ",
    "  . - ~|        |-^-|        |~ - .  ",
    "{      |        |   |        |      }",
    "        `.____.'     `.____.'       "
    };
static const size_t side_art_lines = sizeof(side_art)/sizeof(side_art[0]);

static void print_summary(SysVec *sys, StrVec *files, double sec, long peak_kb, int exited, int code, int sig) {
    /* Sort syscalls by count desc up front */
    for (size_t i=0;i<sys->n;i++)
        for (size_t j=i+1;j<sys->n;j++)
            if (sys->a[j].count > sys->a[i].count) {
                SysCount t = sys->a[i]; sys->a[i] = sys->a[j]; sys->a[j] = t;
            }

    int tw = term_width();

    /* Header */
    printf("\n%s%s╔══════════════════════════════════════════════════════════════════════╗%s\n",
           C_CYAN, C_BOLD, C_RESET);
    printf("%s%s║%s  SANDSTAT - System Call Staticstics Tool - Ver-0.1 %s\n", C_CYAN, C_BOLD, C_RESET, C_CYAN);
    printf("╠══════════════════════════════════════════════════════════════════════╣%s\n", C_RESET);

    /* Exec stats */
    printf("║ %sWall time%s  : %s%.3f s%s\n", C_BOLD, C_RESET, C_GREEN, sec, C_RESET);
    if (peak_kb >= 0) {
        printf("║ %sPeak RSS%s   : %s%ld kB (%.2f MB)%s\n", C_BOLD, C_RESET, C_GREEN, peak_kb, peak_kb/1024.0, C_RESET);
    }
    if (exited) {
        printf("║ %sExit status%s: %s%d%s\n", C_BOLD, C_RESET, C_GREEN, code, C_RESET);
    } else {
        printf("║ %sSignal%s     : %s%d%s\n", C_BOLD, C_RESET, C_RED, sig, C_RESET);
    }

    printf("%s╠══════════════════════════════════════════════════════════════════════╣%s\n", C_CYAN, C_RESET);

    /* Table: Syscall / Description / Count
       Layout adapts to terminal width:
       - NAME_W dynamic to the longest syscall (min 10, max 24)
       - COUNT_W based on largest count width (min 5)
       - DESC_W = remaining space
    */
    size_t show = sys->n < 20 ? sys->n : 20;

    int longest_name = 10;
    unsigned long max_count = 0;
    for (size_t i=0;i<show;i++) {
        const char *nm = syscall_name(sys->a[i].no);
        if (!nm) nm = "(unknown)";
        int len = (int)strlen(nm);
        if (len > longest_name) longest_name = len;
        if (sys->a[i].count > max_count) max_count = sys->a[i].count;
    }
    if (longest_name > 24) longest_name = 24;
    if (longest_name < 10) longest_name = 10;

    int COUNT_W = num_digits_unsigned_unsigned(max_count);
    if (COUNT_W < 5) COUNT_W = 5;
    /* Borders and paddings eat ~6 chars; reserve */
    int NAME_W = longest_name;
    /* after computing NAME_W and COUNT_W */
    int DESC_W = tw - (NAME_W + COUNT_W + 9);

    /* NEW: hard cap the description width */
    int MAX_DESC_W = 48;                       /* tweak to taste */
    const char *env_descw = getenv("SANDSTAT_DESCW");
    if (env_descw) {
        int v = atoi(env_descw);
        if (v >= 12 && v <= 200) MAX_DESC_W = v;   /* allow override via env */
    }
    if (DESC_W > MAX_DESC_W) DESC_W = MAX_DESC_W;

    /* keep your existing safety floor */
    if (DESC_W < 18) {
        int delta = 18 - DESC_W;
        NAME_W -= delta;
        if (NAME_W < 8) NAME_W = 8;
        DESC_W = tw - (NAME_W + COUNT_W + 9);
        if (DESC_W < 12) DESC_W = 12;
    }


    /* Header row */
    printf("║ %s%-*s%s  %s%-*s%s  %s%*s%s ║\n",
           C_BOLD, NAME_W, "Syscall", C_RESET,
           C_BOLD, DESC_W, "Description", C_RESET,
           C_BOLD, COUNT_W, "Count", C_RESET);

    /* Underline that matches EXACT table width (no full-terminal dashes) */
    printf("║ ");
    for (int i = 0; i < NAME_W; i++) putchar('-');
    printf("  ");
    for (int i = 0; i < DESC_W; i++) putchar('-');
    printf("  ");
    for (int i = 0; i < COUNT_W; i++) putchar('-');
    printf(" ║\n");



    if (show == 0) {
        printf("║ %s(none captured)%s\n", C_DIM, C_RESET);
    } else {
        for (size_t i=0;i<show;i++) {
            const char *nm = syscall_name(sys->a[i].no);
            const char *desc = syscall_desc(sys->a[i].no);
            if (!nm) nm = "(unknown)";
            if (!desc) desc = "Unknown system call function";

            /* Zebra stripe for readability */
            int stripe = (int)(i & 1);
            const char *rowc = stripe ? C_RESET : C_DIM;

            printf("║ %s%-*s%s  ", C_CYAN, NAME_W, nm, C_RESET);
            fputs(C_YELLOW, stdout);
            print_fit(desc, DESC_W);
            fputs(C_RESET, stdout);
            printf("  %s%*lu%s ║\n", C_GREEN, COUNT_W, sys->a[i].count, rowc);

        }
    }

    printf("%s╠══════════════════════════════════════════════════════════════════════╣%s\n", C_CYAN, C_RESET);

    /* Files section */
    printf("║ %sFiles Opened/Created%s\n", C_BOLD, C_RESET);
    if (files->n == 0) {
        printf("║ %s(none captured)%s\n", C_DIM, C_RESET);
    } else {
        for (size_t i=0;i<files->n;i++) {
            printf("║   %s%s%s\n", C_MAGENTA, files->a[i], C_RESET);
        }
    }

    printf("%s╚══════════════════════════════════════════════════════════════════════╝%s\n\n", C_CYAN, C_RESET);

    /* JSON output (unchanged) */
    if (out_path) {
        FILE *o = fopen(out_path, "w");
        if (!o) { perror("fopen -o"); return; }
        fprintf(o, "{\n");
        fprintf(o, "  \"wall_time_sec\": %.6f,\n", sec);
        fprintf(o, "  \"peak_rss_kb\": %ld,\n", peak_kb);
        if (exited) fprintf(o, "  \"exit_status\": %d,\n", code);
        else        fprintf(o, "  \"term_signal\": %d,\n", sig);
        fprintf(o, "  \"syscalls\": [\n");
        for (size_t i=0;i<sys->n;i++) {
            const char *nm = syscall_name(sys->a[i].no);
            const char *desc = syscall_desc(sys->a[i].no);
            fprintf(o, "    {\"name\":\"%s\",\"count\":%lu,\"desc\":\"",
                    nm?nm:"unknown", sys->a[i].count);
            /* escape quotes/backslashes in desc */
            for (const char *p = desc?desc:""; *p; ++p) {
                if (*p=='\\' || *p=='"') fputc('\\', o);
                fputc(*p, o);
            }
            fprintf(o, "\"}%s\n", (i+1<sys->n)?",":"");
        }
        fprintf(o, "  ],\n  \"files\": [\n");
        for (size_t i=0;i<files->n;i++) {
            const char *s = files->a[i];
            fputs("    \"", o);
            for (const char *p = s; *p; ++p) {
                if (*p=='\\' || *p=='"') fputc('\\', o);
                fputc(*p, o);
            }
            fprintf(o, "\"%s\n", (i+1<files->n)?",":"");
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
    /* quick long-flag check for --no-color before getopt */
    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i], "--no-color")==0) {
            use_color = 0;
            /* remove the arg by shifting; keep it simple */
            for (int j=i;j<argc-1;j++) argv[j] = argv[j+1];
            argc--;
            break;
        }
    }

    while ((opt = getopt(argc, argv, "+vo:")) != -1) {
        switch (opt) {
            case 'v': verbose = 1; break;
            case 'o': out_path = optarg; break;
            default: usage(argv[0]); return 2;
        }
    }

    /* Auto-disable color if not TTY or NO_COLOR is set */
    if (!isatty(STDOUT_FILENO) || getenv("NO_COLOR")) use_color = 0;


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

    /* --- extra resource stats via getrusage (tiny add) --- */
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) == 0) {
        double u = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6;
        double s = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
        double cpu = u + s;
        printf("║ %sResource usage%s  user=%s%.3fs%s  sys=%s%.3fs%s  cpu=%s%.3fs%s\n",
               C_BOLD, C_RESET, C_GREEN, u, C_RESET, C_GREEN, s, C_RESET, C_GREEN, cpu, C_RESET);
        printf("║ faults(min/maj)=%s%ld%s/%s%ld%s  ctxsw(vol/invol)=%s%ld%s/%s%ld%s\n\n",
               C_YELLOW, ru.ru_minflt, C_RESET, C_YELLOW, ru.ru_majflt, C_RESET,
               C_YELLOW, ru.ru_nvcsw, C_RESET, C_YELLOW, ru.ru_nivcsw, C_RESET);
    }
    /* --- end extra --- */



    free(sc.a);
    strvec_free(&files);
    return exited_normally ? exit_status_code : 128 + term_sig;
}

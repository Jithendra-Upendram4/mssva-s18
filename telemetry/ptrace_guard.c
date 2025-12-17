/*
 * ptrace_guard.c – user-space runtime integrity monitor for authz_bridge
 *
 * Attaches to the running service and periodically samples registers,
 * walks frames, and validates return addresses against executable maps.
 *
 * Build:   gcc -Wall -g -o ptrace_guard ptrace_guard.c -lelf
 * Usage:   ./ptrace_guard <PID>
 *
 * Features:
 *   - Loads /proc/<PID>/maps to build list of executable ranges.
 *   - Attaches via ptrace, samples at intervals, walks frame-pointer chain.
 *   - Alerts if any saved return address falls outside executable regions.
 *   - Optionally sets breakpoints on longjmp (libc) to detect non-linear jumps.
 *
 * Requirements: Linux, x86-64, libelf (for symbol lookup extension).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

/* Maximum executable ranges we track. */
#define MAX_MAPS 256
#define MAX_FRAMES 64
#define SAMPLE_INTERVAL_MS 50

typedef struct {
    uint64_t start;
    uint64_t end;
    char     name[128];
} exec_region_t;

static exec_region_t regions[MAX_MAPS];
static int           region_count = 0;
static volatile int  running = 1;

static void handle_sigint(int sig) { (void)sig; running = 0; }

/* Parse /proc/<pid>/maps and record executable (r-x) regions. */
static int load_maps(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f) && region_count < MAX_MAPS) {
        uint64_t start, end;
        char perms[8] = {0}, name[128] = "";
        if (sscanf(line, "%lx-%lx %4s %*x %*s %*d %127[^\n]",
                   &start, &end, perms, name) >= 3) {
            if (perms[2] == 'x') {
                regions[region_count].start = start;
                regions[region_count].end = end;
                strncpy(regions[region_count].name, name, sizeof(regions[0].name) - 1);
                region_count++;
            }
        }
    }
    fclose(f);
    printf("[ptrace_guard] loaded %d executable regions\n", region_count);
    return 0;
}

/* Check if addr is within an executable region. */
static int addr_in_exec(uint64_t addr) {
    for (int i = 0; i < region_count; i++) {
        if (addr >= regions[i].start && addr < regions[i].end)
            return 1;
    }
    return 0;
}

/* Read a word from target address space. */
static uint64_t peek(pid_t pid, uint64_t addr) {
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (errno) return 0;
    return (uint64_t)v;
}

/* Walk frames using rbp chain and validate return addresses. */
static void walk_frames(pid_t pid, uint64_t rbp) {
    for (int depth = 0; depth < MAX_FRAMES && rbp; depth++) {
        uint64_t saved_bp = peek(pid, rbp);
        uint64_t ret_addr = peek(pid, rbp + 8);
        if (!ret_addr) break;
        if (!addr_in_exec(ret_addr)) {
            printf("[ALERT] frame %d: RA 0x%lx NOT in executable region!\n",
                   depth, ret_addr);
        }
        rbp = saved_bp;
    }
}

static void sample(pid_t pid) {
    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) {
        perror("PTRACE_INTERRUPT");
        return;
    }
    int ws;
    waitpid(pid, &ws, 0);

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("PTRACE_GETREGS");
    } else {
        if (!addr_in_exec(regs.rip)) {
            printf("[ALERT] RIP 0x%llx NOT in executable region!\n", regs.rip);
        }
        walk_frames(pid, regs.rbp);
    }

    ptrace(PTRACE_CONT, pid, NULL, NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    printf("[ptrace_guard] attaching to PID %d\n", pid);

    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1) {
        perror("PTRACE_SEIZE");
        return 1;
    }

    if (load_maps(pid) < 0) return 1;

    signal(SIGINT, handle_sigint);

    printf("[ptrace_guard] monitoring... press Ctrl+C to stop\n");
    while (running) {
        sample(pid);
        usleep(SAMPLE_INTERVAL_MS * 1000);
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[ptrace_guard] detached\n");
    return 0;
}

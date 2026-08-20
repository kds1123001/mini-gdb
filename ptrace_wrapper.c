#include "ptrace_wrapper.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>

int tgt_launch(target_t *t, const char *path, char *const argv[]) {
    memset(t, 0, sizeof(*t));
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(TRACEME)");
            _exit(127);
        }
        execv(path, argv);
        perror("execv");
        _exit(127);
    }

    t->pid = pid;
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFSTOPPED(status)) return -1;

    ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(long)PTRACE_O_EXITKILL);
    t->load_base = tgt_find_load_base(pid, path);
    t->running = 1;
    return 0;
}

int tgt_attach(target_t *t, pid_t pid) {
    memset(t, 0, sizeof(*t));
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    t->pid = pid;
    t->running = 1;

    char exe[64], resolved[4096];
    snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
    ssize_t n = readlink(exe, resolved, sizeof(resolved) - 1);
    if (n > 0) {
        resolved[n] = 0;
        t->load_base = tgt_find_load_base(pid, resolved);
    }
    return 0;
}

int tgt_detach(target_t *t) {
    if (!t->running) return -1;
    long r = ptrace(PTRACE_DETACH, t->pid, NULL, NULL);
    t->running = 0;
    return r < 0 ? -1 : 0;
}

int tgt_kill(target_t *t) {
    if (!t->pid) return -1;
    kill(t->pid, SIGKILL);
    int status;
    waitpid(t->pid, &status, 0);
    t->running = 0;
    t->exited = 1;
    return 0;
}

int tgt_wait(target_t *t, int *status_out) {
    int status;
    pid_t r = waitpid(t->pid, &status, 0);
    if (r < 0) return -1;
    *status_out = status;
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        t->running = 0;
        t->exited = 1;
        t->exit_status = status;
    }
    return 0;
}

int tgt_cont(target_t *t, int sig) {
    return ptrace(PTRACE_CONT, t->pid, NULL, (void *)(long)sig) < 0 ? -1 : 0;
}

int tgt_singlestep(target_t *t, int sig) {
    return ptrace(PTRACE_SINGLESTEP, t->pid, NULL, (void *)(long)sig) < 0 ? -1 : 0;
}

int tgt_getregs(target_t *t, struct user_regs_struct *regs) {
    return ptrace(PTRACE_GETREGS, t->pid, NULL, regs) < 0 ? -1 : 0;
}

int tgt_setregs(target_t *t, struct user_regs_struct *regs) {
    return ptrace(PTRACE_SETREGS, t->pid, NULL, regs) < 0 ? -1 : 0;
}

long tgt_peektext(target_t *t, uint64_t addr, int *err) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, t->pid, (void *)addr, NULL);
    if (err) *err = (word == -1 && errno != 0) ? -1 : 0;
    return word;
}

int tgt_poketext(target_t *t, uint64_t addr, long word) {
    return ptrace(PTRACE_POKETEXT, t->pid, (void *)addr, (void *)word) < 0 ? -1 : 0;
}

int tgt_read_mem(target_t *t, uint64_t addr, void *buf, size_t len) {
    size_t words = (len + sizeof(long) - 1) / sizeof(long);
    long *dst = (long *)buf;
    for (size_t i = 0; i < words; i++) {
        int err;
        long w = tgt_peektext(t, addr + i * sizeof(long), &err);
        if (err) return -1;
        dst[i] = w;
    }
    return 0;
}

int tgt_write_mem(target_t *t, uint64_t addr, const void *buf, size_t len) {
    size_t words = len / sizeof(long);
    size_t rem = len % sizeof(long);
    const long *src = (const long *)buf;
    for (size_t i = 0; i < words; i++) {
        if (tgt_poketext(t, addr + i * sizeof(long), src[i]) < 0) return -1;
    }
    if (rem) {
        int err;
        long orig = tgt_peektext(t, addr + words * sizeof(long), &err);
        if (err) return -1;
        long patched;
        memcpy(&patched, &orig, sizeof(long));
        memcpy(&patched, (const char *)buf + words * sizeof(long), rem);
        if (tgt_poketext(t, addr + words * sizeof(long), patched) < 0) return -1;
    }
    return 0;
}

uint64_t tgt_find_load_base(pid_t pid, const char *exe_path) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[1024];
    uint64_t base = 0;
    const char *base_name = strrchr(exe_path, '/');
    base_name = base_name ? base_name + 1 : exe_path;

    while (fgets(line, sizeof(line), f)) {
        unsigned long start;
        char path[768];
        path[0] = 0;
        if (sscanf(line, "%lx-%*x %*s %*s %*s %*s %767s", &start, path) >= 1) {
            const char *nm = strrchr(path, '/');
            nm = nm ? nm + 1 : path;
            if (strcmp(nm, base_name) == 0) {
                base = start;
                break;
            }
        }
    }
    fclose(f);
    return base;
}

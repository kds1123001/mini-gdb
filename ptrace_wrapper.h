#ifndef PTRACE_WRAPPER_H
#define PTRACE_WRAPPER_H

#include <stdint.h>
#include <sys/user.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    uint64_t load_base;
    int running;
    int exited;
    int exit_status;
} target_t;

int tgt_launch(target_t *t, const char *path, char *const argv[]);
int tgt_attach(target_t *t, pid_t pid);
int tgt_detach(target_t *t);
int tgt_kill(target_t *t);

int tgt_wait(target_t *t, int *status_out);
int tgt_cont(target_t *t, int sig);
int tgt_singlestep(target_t *t, int sig);

int tgt_getregs(target_t *t, struct user_regs_struct *regs);
int tgt_setregs(target_t *t, struct user_regs_struct *regs);

long tgt_peektext(target_t *t, uint64_t addr, int *err);
int tgt_poketext(target_t *t, uint64_t addr, long word);

int tgt_read_mem(target_t *t, uint64_t addr, void *buf, size_t len);
int tgt_write_mem(target_t *t, uint64_t addr, const void *buf, size_t len);

uint64_t tgt_find_load_base(pid_t pid, const char *exe_path);

#endif

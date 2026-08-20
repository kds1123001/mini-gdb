#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>

#include "elf_parser.h"
#include "ptrace_wrapper.h"
#include "breakpoint.h"
#include "dbgregs.h"

typedef struct {
    target_t t;
    elf_image_t img;
    bp_table_t bpt;
    wp_table_t wpt;
    char exe_path[4096];
    int loaded;
} session_t;

/* returns the address as it appears in the ELF file (no load-base applied) */
static uint64_t resolve_addr_raw(session_t *s, const char *arg) {
    if (arg[0] == '0' && arg[1] == 'x') return strtoul(arg, NULL, 16);
    uint64_t sym_addr;
    if (s->loaded && elf_resolve_symbol(&s->img, arg, &sym_addr) == 0) return sym_addr;
    return strtoul(arg, NULL, 0);
}

/* returns the live, relocated address in the target's address space.
 * only valid once the target is running (load_base known). */
static uint64_t resolve_addr(session_t *s, const char *arg) {
    uint64_t raw = resolve_addr_raw(s, arg);
    return s->img.is_pie ? s->t.load_base + raw : raw;
}

static void print_regs(struct user_regs_struct *r) {
    printf("rip=0x%016llx rsp=0x%016llx rbp=0x%016llx\n", r->rip, r->rsp, r->rbp);
    printf("rax=0x%016llx rbx=0x%016llx rcx=0x%016llx rdx=0x%016llx\n", r->rax, r->rbx, r->rcx, r->rdx);
    printf("rsi=0x%016llx rdi=0x%016llx r8=0x%016llx  r9=0x%016llx\n", r->rsi, r->rdi, r->r8, r->r9);
    printf("r10=0x%016llx r11=0x%016llx r12=0x%016llx r13=0x%016llx\n", r->r10, r->r11, r->r12, r->r13);
    printf("r14=0x%016llx r15=0x%016llx eflags=0x%llx\n", r->r14, r->r15, r->eflags);
}

static void handle_stop(session_t *s, int status) {
    if (WIFEXITED(status)) {
        printf("* target exited, status %d\n", WEXITSTATUS(status));
        return;
    }
    if (WIFSIGNALED(status)) {
        printf("* target killed by signal %d\n", WTERMSIG(status));
        return;
    }
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        struct user_regs_struct regs;
        tgt_getregs(&s->t, &regs);

        if (sig == SIGTRAP) {
            int idx = bp_find(&s->bpt, regs.rip - 1);
            if (idx >= 0) {
                regs.rip -= 1;
                tgt_setregs(&s->t, &regs);
                printf("* breakpoint hit: [%d] 0x%016llx %s\n", idx, regs.rip, s->bpt.bps[idx].label);
                return;
            }
            int wpidx = wp_which_triggered(&s->wpt, &s->t);
            if (wpidx >= 0) {
                printf("* watchpoint hit: DR%d addr=0x%016lx rip=0x%016llx\n", wpidx, s->wpt.wps[wpidx].addr, regs.rip);
                return;
            }
            printf("* trap at rip=0x%016llx\n", regs.rip);
            return;
        }
        printf("* stopped by signal %d at rip=0x%016llx\n", sig, regs.rip);
    }
}

static void cmd_load(session_t *s, char *path) {
    if (s->loaded) elf_unload(&s->img);
    if (elf_load(path, &s->img) < 0) {
        printf("! failed to load ELF: %s\n", path);
        return;
    }
    strncpy(s->exe_path, path, sizeof(s->exe_path) - 1);
    s->loaded = 1;
    printf("* loaded %s (%s, entry=0x%lx, %zu symbols)\n", path,
           s->img.is_pie ? "PIE" : "static", s->img.ehdr->e_entry, s->img.sym_count);
}

static void cmd_run(session_t *s, char *args) {
    if (!s->loaded) { printf("! no binary loaded, use: load <path>\n"); return; }
    char *argv[32];
    int argc = 0;
    argv[argc++] = s->exe_path;
    char *tok = strtok(args, " ");
    while (tok && argc < 31) { argv[argc++] = tok; tok = strtok(NULL, " "); }
    argv[argc] = NULL;

    if (tgt_launch(&s->t, s->exe_path, argv) < 0) {
        printf("! launch failed\n");
        return;
    }
    printf("* launched pid=%d load_base=0x%lx\n", s->t.pid, s->t.load_base);

    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        breakpoint_t *bp = &s->bpt.bps[i];
        if (bp->in_use && bp->enabled) {
            /* relocate the raw ELF-file offset by the now-known load base (PIE only) */
            if (s->img.is_pie) bp->addr += s->t.load_base;
            int err;
            long word = tgt_peektext(&s->t, bp->addr, &err);
            if (!err) {
                bp->orig_byte = word & 0xFF;
                tgt_poketext(&s->t, bp->addr, (word & ~0xFFL) | INT3_OPCODE);
            }
        }
    }
}

static void cmd_attach(session_t *s, char *pid_str) {
    pid_t pid = atoi(pid_str);
    if (tgt_attach(&s->t, pid) < 0) {
        printf("! attach failed (need CAP_SYS_PTRACE / matching uid / yama ptrace_scope)\n");
        return;
    }
    printf("* attached to pid=%d load_base=0x%lx\n", pid, s->t.load_base);
}

int main(int argc, char **argv) {
    session_t s;
    memset(&s, 0, sizeof(s));
    bp_table_init(&s.bpt);
    wp_table_init(&s.wpt);

    if (argc > 1) cmd_load(&s, argv[1]);

    char line[512];
    printf("mini-gdb> ");
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        char *cmd = strtok(line, " ");
        char *rest = strtok(NULL, "");

        if (!cmd) { printf("mini-gdb> "); continue; }

        if (strcmp(cmd, "load") == 0 && rest) {
            cmd_load(&s, rest);
        } else if (strcmp(cmd, "run") == 0) {
            cmd_run(&s, rest ? rest : "");
        } else if (strcmp(cmd, "attach") == 0 && rest) {
            cmd_attach(&s, rest);
        } else if (strcmp(cmd, "detach") == 0) {
            tgt_detach(&s.t);
            printf("* detached\n");
        } else if (strcmp(cmd, "break") == 0 && rest) {
            if (!s.t.running) {
                /* not launched yet: store the raw ELF-file address; load_base
                 * (only known post-launch for PIE binaries) is applied in cmd_run */
                uint64_t raw = resolve_addr_raw(&s, rest);
                int idx = -1;
                for (int i = 0; i < MAX_BREAKPOINTS; i++) if (!s.bpt.bps[i].in_use) { idx = i; break; }
                if (idx >= 0) {
                    s.bpt.bps[idx].addr = raw;
                    s.bpt.bps[idx].in_use = 1;
                    s.bpt.bps[idx].enabled = 1;
                    strncpy(s.bpt.bps[idx].label, rest, sizeof(s.bpt.bps[idx].label) - 1);
                    printf("* pending breakpoint [%d] at raw offset 0x%016lx (%s)\n", idx, raw, rest);
                }
            } else {
                uint64_t addr = resolve_addr(&s, rest);
                int idx = bp_set(&s.bpt, &s.t, addr, rest);
                if (idx >= 0) printf("* breakpoint [%d] at 0x%016lx (%s)\n", idx, addr, rest);
                else printf("! failed to set breakpoint\n");
            }
        } else if (strcmp(cmd, "watch") == 0 && rest) {
            char *addr_s = strtok(rest, " ");
            char *mode_s = strtok(NULL, " ");
            char *len_s = strtok(NULL, " ");
            uint64_t addr = resolve_addr(&s, addr_s);
            wp_mode_t mode = WP_WRITE;
            if (mode_s) {
                if (strcmp(mode_s, "exec") == 0) mode = WP_EXEC;
                else if (strcmp(mode_s, "rw") == 0) mode = WP_RW;
                else if (strcmp(mode_s, "write") == 0) mode = WP_WRITE;
            }
            int len = len_s ? atoi(len_s) : 4;
            int slot = wp_set(&s.wpt, &s.t, addr, mode, len);
            if (slot >= 0) printf("* watchpoint DR%d at 0x%016lx\n", slot, addr);
            else printf("! failed to set watchpoint\n");
        } else if (strcmp(cmd, "cont") == 0 || strcmp(cmd, "c") == 0) {
            if (!s.t.running) { printf("! not running\n"); }
            else {
                struct user_regs_struct regs;
                tgt_getregs(&s.t, &regs);
                int idx = bp_find(&s.bpt, regs.rip);
                if (idx >= 0) bp_step_over(&s.bpt, &s.t, idx);
                if (s.t.running) {
                    tgt_cont(&s.t, 0);
                    int status;
                    tgt_wait(&s.t, &status);
                    handle_stop(&s, status);
                }
            }
        } else if (strcmp(cmd, "step") == 0 || strcmp(cmd, "s") == 0) {
            if (!s.t.running) { printf("! not running\n"); }
            else {
                tgt_singlestep(&s.t, 0);
                int status;
                tgt_wait(&s.t, &status);
                handle_stop(&s, status);
            }
        } else if (strcmp(cmd, "regs") == 0) {
            if (!s.t.running) { printf("! not running\n"); }
            else {
                struct user_regs_struct regs;
                tgt_getregs(&s.t, &regs);
                print_regs(&regs);
            }
        } else if (strcmp(cmd, "mem") == 0 && rest) {
            char *addr_s = strtok(rest, " ");
            char *len_s = strtok(NULL, " ");
            uint64_t addr = resolve_addr(&s, addr_s);
            int len = len_s ? atoi(len_s) : 32;
            unsigned char buf[256];
            if (len > 256) len = 256;
            if (tgt_read_mem(&s.t, addr, buf, len) == 0) {
                for (int i = 0; i < len; i++) {
                    if (i % 16 == 0) printf("%s0x%016lx: ", i ? "\n" : "", addr + i);
                    printf("%02x ", buf[i]);
                }
                printf("\n");
            } else {
                printf("! read failed\n");
            }
        } else if (strcmp(cmd, "syms") == 0) {
            if (s.loaded) elf_list_symbols(&s.img);
        } else if (strcmp(cmd, "bplist") == 0) {
            bp_list(&s.bpt);
        } else if (strcmp(cmd, "wplist") == 0) {
            wp_list(&s.wpt);
        } else if (strcmp(cmd, "kill") == 0) {
            tgt_kill(&s.t);
            printf("* killed\n");
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "q") == 0) {
            if (s.t.running) tgt_kill(&s.t);
            break;
        } else {
            printf("! unknown command: %s\n", cmd);
        }

        printf("mini-gdb> ");
    }

    if (s.loaded) elf_unload(&s.img);
    return 0;
}

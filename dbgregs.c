#include "dbgregs.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define DR_OFFSET(n) (offsetof(struct user, u_debugreg[n]))

static long peek_dr(target_t *t, int n) {
    errno = 0;
    return ptrace(PTRACE_PEEKUSER, t->pid, (void *)DR_OFFSET(n), NULL);
}

static int poke_dr(target_t *t, int n, long val) {
    return ptrace(PTRACE_POKEUSER, t->pid, (void *)DR_OFFSET(n), (void *)val) < 0 ? -1 : 0;
}

static int len_encoding(int len) {
    switch (len) {
        case 1: return 0x0;
        case 2: return 0x1;
        case 4: return 0x3;
        case 8: return 0x2;
        default: return 0x0;
    }
}

void wp_table_init(wp_table_t *tbl) {
    memset(tbl, 0, sizeof(*tbl));
}

int wp_set(wp_table_t *tbl, target_t *t, uint64_t addr, wp_mode_t mode, int len) {
    int slot = -1;
    for (int i = 0; i < MAX_WATCHPOINTS; i++) {
        if (!tbl->wps[i].in_use) { slot = i; break; }
    }
    if (slot < 0) return -1;

    if (poke_dr(t, slot, (long)addr) < 0) return -1;

    long dr7 = peek_dr(t, 7);
    if (dr7 == -1 && errno) return -1;

    dr7 |= (1L << (slot * 2));

    int rw = (mode == WP_EXEC) ? 0x0 : (mode == WP_WRITE) ? 0x1 : (mode == WP_IO) ? 0x2 : 0x3;
    int lenc = len_encoding(len);

    int rw_shift = 16 + slot * 4;
    int len_shift = 18 + slot * 4;
    dr7 &= ~(0x3L << rw_shift);
    dr7 &= ~(0x3L << len_shift);
    dr7 |= ((long)rw << rw_shift);
    dr7 |= ((long)lenc << len_shift);

    if (poke_dr(t, 7, dr7) < 0) return -1;

    tbl->wps[slot].addr = addr;
    tbl->wps[slot].mode = mode;
    tbl->wps[slot].len = len;
    tbl->wps[slot].slot = slot;
    tbl->wps[slot].in_use = 1;
    return slot;
}

int wp_remove(wp_table_t *tbl, target_t *t, int slot) {
    if (slot < 0 || slot >= MAX_WATCHPOINTS || !tbl->wps[slot].in_use) return -1;
    long dr7 = peek_dr(t, 7);
    if (dr7 == -1 && errno) return -1;
    dr7 &= ~(1L << (slot * 2));
    if (poke_dr(t, 7, dr7) < 0) return -1;
    tbl->wps[slot].in_use = 0;
    return 0;
}

void wp_list(wp_table_t *tbl) {
    static const char *mode_names[] = {"exec", "write", "io", "rw"};
    for (int i = 0; i < MAX_WATCHPOINTS; i++) {
        if (!tbl->wps[i].in_use) continue;
        printf("[DR%d] 0x%016lx  %s  len=%d\n", i, tbl->wps[i].addr,
               mode_names[tbl->wps[i].mode], tbl->wps[i].len);
    }
}

int wp_which_triggered(wp_table_t *tbl, target_t *t) {
    long dr6 = peek_dr(t, 6);
    if (dr6 == -1 && errno) return -1;
    for (int i = 0; i < MAX_WATCHPOINTS; i++) {
        if (dr6 & (1L << i)) return i;
    }
    (void)tbl;
    return -1;
}

#include "breakpoint.h"
#include <stdio.h>
#include <string.h>
#include <sys/user.h>

void bp_table_init(bp_table_t *tbl) {
    memset(tbl, 0, sizeof(*tbl));
}

int bp_find(bp_table_t *tbl, uint64_t addr) {
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (tbl->bps[i].in_use && tbl->bps[i].addr == addr) return i;
    }
    return -1;
}

int bp_set(bp_table_t *tbl, target_t *t, uint64_t addr, const char *label) {
    if (bp_find(tbl, addr) >= 0) return -1;
    int slot = -1;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (!tbl->bps[i].in_use) { slot = i; break; }
    }
    if (slot < 0) return -1;

    int err;
    long word = tgt_peektext(t, addr, &err);
    if (err) return -1;

    unsigned char orig = word & 0xFF;
    long patched = (word & ~0xFFL) | INT3_OPCODE;
    if (tgt_poketext(t, addr, patched) < 0) return -1;

    tbl->bps[slot].addr = addr;
    tbl->bps[slot].orig_byte = orig;
    tbl->bps[slot].enabled = 1;
    tbl->bps[slot].in_use = 1;
    if (label) strncpy(tbl->bps[slot].label, label, sizeof(tbl->bps[slot].label) - 1);
    return slot;
}

int bp_disable_at(bp_table_t *tbl, target_t *t, uint64_t addr) {
    int idx = bp_find(tbl, addr);
    if (idx < 0 || !tbl->bps[idx].enabled) return -1;
    int err;
    long word = tgt_peektext(t, addr, &err);
    if (err) return -1;
    long restored = (word & ~0xFFL) | tbl->bps[idx].orig_byte;
    if (tgt_poketext(t, addr, restored) < 0) return -1;
    tbl->bps[idx].enabled = 0;
    return 0;
}

int bp_enable_at(bp_table_t *tbl, target_t *t, uint64_t addr) {
    int idx = bp_find(tbl, addr);
    if (idx < 0 || tbl->bps[idx].enabled) return -1;
    int err;
    long word = tgt_peektext(t, addr, &err);
    if (err) return -1;
    long patched = (word & ~0xFFL) | INT3_OPCODE;
    if (tgt_poketext(t, addr, patched) < 0) return -1;
    tbl->bps[idx].enabled = 1;
    return 0;
}

int bp_remove(bp_table_t *tbl, target_t *t, uint64_t addr) {
    int idx = bp_find(tbl, addr);
    if (idx < 0) return -1;
    if (tbl->bps[idx].enabled) bp_disable_at(tbl, t, addr);
    tbl->bps[idx].in_use = 0;
    return 0;
}

void bp_list(bp_table_t *tbl) {
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (!tbl->bps[i].in_use) continue;
        printf("[%d] 0x%016lx  %s  %s\n", i, tbl->bps[i].addr,
               tbl->bps[i].enabled ? "enabled" : "disabled",
               tbl->bps[i].label);
    }
}

int bp_step_over(bp_table_t *tbl, target_t *t, int idx) {
    breakpoint_t *bp = &tbl->bps[idx];
    struct user_regs_struct regs;
    if (tgt_getregs(t, &regs) < 0) return -1;

    if (bp_disable_at(tbl, t, bp->addr) < 0) return -1;

    regs.rip = bp->addr;
    if (tgt_setregs(t, &regs) < 0) return -1;

    if (tgt_singlestep(t, 0) < 0) return -1;
    int status;
    if (tgt_wait(t, &status) < 0) return -1;
    if (t->exited) return 0;

    if (bp_enable_at(tbl, t, bp->addr) < 0) return -1;
    return 0;
}

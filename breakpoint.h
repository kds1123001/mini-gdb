#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdint.h>
#include "ptrace_wrapper.h"

#define MAX_BREAKPOINTS 64
#define INT3_OPCODE 0xCC

typedef struct {
    uint64_t addr;
    unsigned char orig_byte;
    int enabled;
    int in_use;
    char label[64];
} breakpoint_t;

typedef struct {
    breakpoint_t bps[MAX_BREAKPOINTS];
} bp_table_t;

void bp_table_init(bp_table_t *tbl);
int bp_set(bp_table_t *tbl, target_t *t, uint64_t addr, const char *label);
int bp_remove(bp_table_t *tbl, target_t *t, uint64_t addr);
int bp_find(bp_table_t *tbl, uint64_t addr);
int bp_disable_at(bp_table_t *tbl, target_t *t, uint64_t addr);
int bp_enable_at(bp_table_t *tbl, target_t *t, uint64_t addr);
void bp_list(bp_table_t *tbl);
int bp_step_over(bp_table_t *tbl, target_t *t, int idx);

#endif

#ifndef DBGREGS_H
#define DBGREGS_H

#include <stdint.h>
#include "ptrace_wrapper.h"

typedef enum {
    WP_EXEC = 0,
    WP_WRITE = 1,
    WP_IO = 2,
    WP_RW = 3
} wp_mode_t;

typedef struct {
    uint64_t addr;
    wp_mode_t mode;
    int len;
    int slot;
    int in_use;
} watchpoint_t;

#define MAX_WATCHPOINTS 4

typedef struct {
    watchpoint_t wps[MAX_WATCHPOINTS];
} wp_table_t;

void wp_table_init(wp_table_t *tbl);
int wp_set(wp_table_t *tbl, target_t *t, uint64_t addr, wp_mode_t mode, int len);
int wp_remove(wp_table_t *tbl, target_t *t, int slot);
void wp_list(wp_table_t *tbl);
int wp_which_triggered(wp_table_t *tbl, target_t *t);

#endif

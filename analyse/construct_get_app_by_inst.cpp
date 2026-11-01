/*
 * TEST CASES / CONSTRUCTOR: construct_get_app_by_inst
 *
 * The apps map is a tiny runner table of keys "app_%010d" -> app pointers
 * (blaster = 0x1, harvester = 0x2, analytics = 0x8, inst_max-1 bit 22).
 *
 * Cases: each registered inst found, an unregistered inst, inst 0,
 * INT_MAX (10 digits), -1, INT_MIN (15-char key), and a large bit value.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

char   gai_slot[GAI_SLOT_SZ + GAI_SLOT_PAD];
char   gai_key_seen[64];
size_t gai_key_len;
char   gai_keys[4][32];
void  *gai_vals[4];
int    gai_nentries;
static int gai_app_objs[4];
alignas(16) char gai_mgr_buf[sizeof(wifi_apps_mgr_t) + 64];

get_app_by_inst_test_case_t get_app_by_inst_suite[] = {
    /* name              inst         found key_len */
    { "blaster",         0x1,           1,   14 },
    { "harvester",       0x2,           1,   14 },
    { "analytics",       0x8,           1,   14 },
    { "bit_22",          1 << 22,       1,   14 },
    { "unregistered",    0x4,           0,   14 },
    { "inst_zero",       0,             0,   14 },
    { "inst_int_max",    INT_MAX,       0,   14 },
    { "inst_minus_1",    -1,            0,   14 },
    { "inst_int_min",    INT_MIN,       0,   15 },

    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_get_app_by_inst_input(const get_app_by_inst_test_case_t *tc)
{
    (void)tc;
    int regs[4] = { 0x1, 0x2, 0x8, 1 << 22 };
    gai_nentries = 4;
    for (int i = 0; i < 4; i++) {
        snprintf(gai_keys[i], sizeof(gai_keys[i]), "app_%010d", regs[i]);
        gai_vals[i] = &gai_app_objs[i];
    }
    memset(gai_mgr_buf, 0, sizeof(gai_mgr_buf));
    ((wifi_apps_mgr_t *)gai_mgr_buf)->apps_map = (void *)0x1;   /* not dereferenced by the stub */
    gai_key_seen[0] = 0;
    gai_key_len = 0;
}

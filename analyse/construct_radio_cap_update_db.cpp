/*
 * TEST CASES / CONSTRUCTOR: construct_radio_cap_update_db
 *
 * One radio cap info per case (heap, between poisoned guards): ruid 02:00:00:00:00:01, num_op_classes 7, wifi7_cap bytes by pattern
 * (0 all zero, 1 byte i = i % 251, 2 all 0xFF). sizeof(wifi7_cap) is 488, so the hex string handed to the DB must be 976 characters
 * and, for pattern 1, start with 00010203. PASS = return value, number of row calls and the length of the wifi7 string.
 * Every case that reaches the loop ABORTED on the original code (wifi7_str[256] holds only 255 characters; the loop keeps writing after
 * the buffer): they run last and UNFORKED so a plain `make` stops with the report; FORK_CRASH=1 forks each one. A NULL data pointer
 * was dereferenced as well.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radio_cap_update_db.h"

namespace rcu {
/* {name, op, pattern, null_data, expect_ret, expect_calls, expect_len, crash} */
test_case_t suite[] = {
 {"crash_insert_all_zero",             1, 0, false, 0, 1, 976, true},
 {"crash_insert_pattern",              1, 1, false, 0, 1, 976, true},
 {"crash_update_all_ff",               2, 2, false, 0, 1, 976, true},
 {"crash_delete_row",                  3, 1, false, 0, 1, -1, true},
 {"crash_unknown_op_no_row_call",      99, 1, false, 0, 0, -1, true},
 {"crash_none_op_no_row_call",         0, 0, false, 0, 0, -1, true},
 {"crash_null_data",                   1, 0, true, -1, 0, -1, true},
 {NULL, 0, 0, false, 0, 0, 0, false}
};

void construct_input(const test_case_t *tc)
{
    g_box = (box_t *)calloc(1, sizeof(box_t));
    em_radio_cap_info_t *r = &g_box->info;
    unsigned char m[6] = {2,0,0,0,0,1}; memcpy(r->ruid.mac, m, 6); r->num_op_classes = 7;
    unsigned char *p = (unsigned char *)&r->wifi7_cap;
    for (size_t i = 0; i < sizeof(r->wifi7_cap); i++) p[i] = tc->pattern == 0 ? 0 : tc->pattern == 1 ? (unsigned char)(i % 251) : 0xFF;
    g_calls = 0; g_key[0] = 0; g_wifi7[0] = 0; g_nop = 0;
}
void teardown(void) { free(g_box); g_box = NULL; }
} /* namespace rcu */

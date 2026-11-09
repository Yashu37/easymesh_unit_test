/*
 * UNIT TEST (input constructor): construct_em_wifi_wnm_send_bss_tm_req
 *
 * wifi_wnm_send_bss_tm_req(...) (platform/wifi-emulator) is an empty stub returning 0 for every input: none of the 12 arguments is read and nothing is logged.  The
 * suite pins that contract.  Inputs crossed: all pointer arguments (interface, sta, bss_term_dur, url, nei_rep, mbo_attrs) NULL / pointing into a fully POISONED slab /
 * dangling; every u8 argument 0 / 1 / 0x7F / 0x80 / 0xFF; disassoc_timer 0 / 1 / 100 / -1 / INT_MIN / INT_MAX; nei_rep_len and mbo_len 0 / 1 / 100 / 0xFFFF / SIZE_MAX
 * (not backed by memory: the stub must not read the buffers); repeated calls; and a log slot that is empty / holds text / is almost full / is full.  Checks:
 * return value 0, the slab, the guard slab and the whole log unchanged.  Row: name, ptr_mode, small, timer, len, calls, prefill, expected_ret.
 */
#include <limits.h>
#include <stdint.h>
#include "hwr_ewb.h"

#define OK 0

hwr_ewb_case_t em_wifi_wnm_send_bss_tm_req_suite[] = {
	{ "ptrs_null_zero_values",             0,    0,        0,        0, 1,   0, OK },
	{ "ptrs_slab_zero_values",             1,    0,        0,        0, 1,   0, OK },
	{ "ptrs_dangling_zero_values",         2,    0,        0,        0, 1,   0, OK },
	{ "ptrs_null_typical_values",          0,    1,      100,      100, 1,   0, OK },
	{ "ptrs_slab_typical_values",          1,    1,      100,      100, 1,   0, OK },
	{ "ptrs_dangling_typical_values",      2,    1,      100,      100, 1,   0, OK },
	{ "ptrs_null_u8_0x7f",                 0, 0x7F,      100,      100, 1,   0, OK },
	{ "ptrs_slab_u8_0x7f",                 1, 0x7F,      100,      100, 1,   0, OK },
	{ "ptrs_null_u8_0x80",                 0, 0x80,      100,      100, 1,   0, OK },
	{ "ptrs_slab_u8_0x80",                 1, 0x80,      100,      100, 1,   0, OK },
	{ "ptrs_null_u8_0xff",                 0, 0xFF,      100,      100, 1,   0, OK },
	{ "ptrs_slab_u8_0xff",                 1, 0xFF,      100,      100, 1,   0, OK },
	{ "timer_negative",                    1,    1,       -1,      100, 1,   0, OK },
	{ "timer_int_min",                     1,    1,  INT_MIN,      100, 1,   0, OK },
	{ "timer_int_max",                     1,    1,  INT_MAX,      100, 1,   0, OK },
	{ "len_1",                             1,    1,      100,        1, 1,   0, OK },
	{ "len_0xffff",                        1,    1,      100,   0xFFFF, 1,   0, OK },
	{ "len_size_max_slab",                 1,    1,      100, SIZE_MAX, 1,   0, OK },
	{ "len_size_max_null",                 0,    1,      100, SIZE_MAX, 1,   0, OK },
	{ "len_size_max_dangling",             2,    1,      100, SIZE_MAX, 1,   0, OK },
	{ "all_extremes_slab",                 1, 0xFF,  INT_MIN, SIZE_MAX, 1,   0, OK },
	{ "all_extremes_dangling",             2, 0xFF,  INT_MAX, SIZE_MAX, 1,   0, OK },
	{ "two_calls_slab",                    1,    1,      100,      100, 2,   0, OK },
	{ "ten_calls_null",                    0,    1,      100,      100, 10,  0, OK },
	{ "ten_calls_slab",                    1,    1,      100,      100, 10,  0, OK },
	{ "log_prefilled_1",                   1,    1,      100,      100, 1,   1, OK },
	{ "log_prefilled_100",                 1,    1,      100,      100, 1, 100, OK },
	{ "log_almost_full",                   1,    1,      100,      100, 1, 254, OK },
	{ "log_full",                          1,    1,      100,      100, 1, 255, OK },
	{ "log_full_ptrs_null",                0,    1,      100,      100, 1, 255, OK },
	{ NULL, 0, 0, 0, 0, 0, 0, 0 }
};

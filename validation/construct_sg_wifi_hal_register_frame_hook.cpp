/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_register_frame_hook
 *
 * wifi_hal_register_frame_hook(func).  Inputs crossed: hooks already registered (num_hooks) 0 / 1 / 5 / 10 / 11 / 12 (full) / 13 / 100 and the number of consecutive registrations 1 / 2 / 6 / 12 / 13 / 20.
 * Expected (CORRECT behaviour): while num_hooks < MAX_APPS (12) the callback is stored in the next slot and num_hooks is incremented, earlier slots are kept; when the table is full the callback is dropped,
 * num_hooks stays at most MAX_APPS and nothing outside frame_hooks_fn[] is written.  Rows with last = 1 break the original (the 13th registration writes past frame_hooks_fn[11]): they run LAST.
 */
#include "hwr_wrf.h"

/* name, start_n, calls, last */
hwr_wrf_case_t sg_wifi_hal_register_frame_hook_suite[] = {
	{ "first_hook",               0,  1, 0 },
	{ "two_hooks",                0,  2, 0 },
	{ "six_hooks",                0,  6, 0 },
	{ "start_1_one_more",         1,  1, 0 },
	{ "start_5_five_more",        5,  5, 0 },
	{ "start_10_one_more",       10,  1, 0 },
	{ "start_11_last_free_slot", 11,  1, 0 },
	{ "twelve_hooks_fill_table",  0, 12, 0 },
	{ "start_3_nine_more",        3,  9, 0 },
	/* ---- the original has no limit check: the 13th hook is written past frame_hooks_fn[MAX_APPS] ---- */
	{ "table_full_one_more",     12,  1, 1 },
	{ "table_full_three_more",   12,  3, 1 },
	{ "thirteen_registrations",   0, 13, 1 },
	{ "twenty_registrations",     0, 20, 1 },
	{ "start_11_two_more",       11,  2, 1 },
	{ "start_13",                13,  1, 1 },
	{ "start_100",              100,  1, 1 },
	{ NULL, 0, 0, 0 }
};

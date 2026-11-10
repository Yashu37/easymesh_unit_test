/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_hostApGetErouter0Mac
 *
 * wifi_hal_hostApGetErouter0Mac(out) writes "01:23:12:44:65:ab" (18 bytes with the NUL) into out, or returns -1 for a NULL out.  Inputs crossed: out NULL; out a heap buffer of exactly
 * 18 bytes (any write beyond it aborts under ASan); out a 64-byte slab whose bytes after the first 18 are POISONED; the buffer preset to zeros / 'z' / 0xFF (an old longer string
 * must be replaced and terminated); repeated calls; a log slot that must stay untouched.
 */
#include "hwr_wem.h"

#define OK 0
#define ER -1
/* name, out_mode, fill, calls, prefill, expected_ret */
hwr_wem_case_t sg_wifi_hal_hostApGetErouter0Mac_suite[] = {
	{ "out_null",                  0, 0,    1,   0, ER },
	{ "out_null_two_calls",        0, 0,    2,   0, ER },
	{ "out_null_ten_calls",        0, 0,   10,   0, ER },
	{ "out_exact_18_zeros",        1, 0,    1,   0, OK },
	{ "out_exact_18_z_fill",       1, 'z',  1,   0, OK },
	{ "out_exact_18_0xff_fill",    1, 0xFF, 1,   0, OK },
	{ "out_exact_18_two_calls",    1, 0,    2,   0, OK },
	{ "out_exact_18_ten_calls",    1, 0,   10,   0, OK },
	{ "out_slab64_zeros",          2, 0,    1,   0, OK },
	{ "out_slab64_z_fill",         2, 'z',  1,   0, OK },
	{ "out_slab64_0xff_fill",      2, 0xFF, 1,   0, OK },
	{ "out_slab64_two_calls",      2, 'z',  2,   0, OK },
	{ "out_exact_18_log_prefilled",1, 0,    1, 100, OK },
	{ "out_exact_18_log_full",     1, 0,    1, 255, OK },
	{ "out_null_log_full",         0, 0,    1, 255, ER },
	{ NULL, 0, 0, 0, 0, 0 }
};

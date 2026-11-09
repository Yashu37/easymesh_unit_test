/*
 * UNIT TEST (input constructor): construct_rp_wifi_drv_get_phy_eht_cap_mac
 *
 * wifi_drv_get_phy_eht_cap_mac(eht_capab, tb) (platform/raspberry-pi) is an empty stub (both arguments cast to void): it neither reads nor writes eht_capab or tb
 * and logs nothing.  The suite crosses eht_capab NULL / the runner's struct (fully POISONED) / a dangling pointer with tb NULL / the runner's pointer array (fully
 * POISONED) / a dangling pointer, repeated calls, and a log slot that is empty / holds text / is almost full / is full.  Checks: nothing crashes, the struct,
 * the array, the guard slab and the whole log are unchanged.
 */
#include "hwr_rhe.h"

/* name, eht_mode, tb_mode, calls, prefill */
hwr_rhe_case_t rp_wifi_drv_get_phy_eht_cap_mac_suite[] = {
	{ "both_poisoned_objects",       1, 1,  1,   0 },
	{ "both_null",                   0, 0,  1,   0 },
	{ "eht_null_tb_poisoned",        0, 1,  1,   0 },
	{ "eht_poisoned_tb_null",        1, 0,  1,   0 },
	{ "both_dangling",               2, 2,  1,   0 },
	{ "eht_dangling_tb_poisoned",    2, 1,  1,   0 },
	{ "eht_poisoned_tb_dangling",    1, 2,  1,   0 },
	{ "eht_null_tb_dangling",        0, 2,  1,   0 },
	{ "eht_dangling_tb_null",        2, 0,  1,   0 },
	{ "two_calls_poisoned",          1, 1,  2,   0 },
	{ "three_calls_null",            0, 0,  3,   0 },
	{ "ten_calls_poisoned",          1, 1, 10,   0 },
	{ "log_prefilled_1",             1, 1,  1,   1 },
	{ "log_prefilled_100",           1, 1,  1, 100 },
	{ "log_prefilled_150_two_calls", 1, 1,  2, 150 },
	{ "log_almost_full",             1, 1,  1, 254 },
	{ "log_full",                    1, 1,  1, 255 },
	{ "log_full_null_args",          0, 0,  1, 255 },
	{ "log_full_ten_calls",          1, 1, 10, 255 },
	{ NULL, 0, 0, 0, 0 }
};

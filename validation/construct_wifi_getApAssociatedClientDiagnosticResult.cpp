/*
 * UNIT TEST (input constructor): construct_wifi_getApAssociatedClientDiagnosticResult
 *
 * wifi_getApAssociatedClientDiagnosticResult(ap_index, key, assoc) (platform/banana-pi) is an empty stub that returns RETURN_ERR (-1) for every input:
 * the platform reports the feature as unsupported (same class as wifi_setApIsolationEnable / wifi_getBssLoad), so there is no finding.  It must not
 * read key, write assoc or log.  The suite pins that contract: every combination returns WIFI_HAL_ERROR and leaves the key slab, the assoc slab, the
 * guard slab and the log untouched.  Inputs crossed: ap_index 0 / 1 / 15 / -1 / INT_MIN / INT_MAX, key and assoc each NULL / a fully POISONED runner
 * slab / dangling (0xdeadbeef), repeated calls, and a log slot that is empty / holds text / is almost full / is full.
 * Pointer mode: 0 NULL, 1 poisoned slab, 2 dangling.
 */
#include <limits.h>
#include "hwr_gcl.h"

#define ERR WIFI_HAL_ERROR

/* name, ap_index, key_mode, assoc_mode, calls, prefill, expected_ret */
hwr_gcl_case_t wifi_getApAssociatedClientDiagnosticResult_suite[] = {
	{ "ap_0_valid_slabs",              0, 1, 1,  1,   0, ERR },
	{ "ap_1_valid_slabs",              1, 1, 1,  1,   0, ERR },
	{ "ap_15_valid_slabs",            15, 1, 1,  1,   0, ERR },
	{ "ap_negative_valid_slabs",      -1, 1, 1,  1,   0, ERR },
	{ "ap_int_min_valid_slabs",  INT_MIN, 1, 1,  1,   0, ERR },
	{ "ap_int_max_valid_slabs",  INT_MAX, 1, 1,  1,   0, ERR },
	{ "key_null_assoc_slab",           0, 0, 1,  1,   0, ERR },
	{ "key_slab_assoc_null",           0, 1, 0,  1,   0, ERR },
	{ "key_null_assoc_null",           0, 0, 0,  1,   0, ERR },
	{ "key_dangling_assoc_slab",       0, 2, 1,  1,   0, ERR },
	{ "key_slab_assoc_dangling",       0, 1, 2,  1,   0, ERR },
	{ "key_dangling_assoc_dangling",   0, 2, 2,  1,   0, ERR },
	{ "key_null_assoc_dangling",       0, 0, 2,  1,   0, ERR },
	{ "key_dangling_assoc_null",       0, 2, 0,  1,   0, ERR },
	{ "two_calls_slabs",               0, 1, 1,  2,   0, ERR },
	{ "ten_calls_null",                3, 0, 0, 10,   0, ERR },
	{ "ap_negative_null_pointers",    -1, 0, 0,  1,   0, ERR },
	{ "log_prefilled_1",               0, 1, 1,  1,   1, ERR },
	{ "log_prefilled_100",             0, 1, 1,  1, 100, ERR },
	{ "log_almost_full",               0, 1, 1,  1, 254, ERR },
	{ "log_full",                      0, 1, 1,  1, 255, ERR },
	{ "log_full_null_pointers",        0, 0, 0,  1, 255, ERR },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};

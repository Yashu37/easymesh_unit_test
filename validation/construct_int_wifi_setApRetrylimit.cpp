/*
 * UNIT TEST (input constructor): construct_int_wifi_setApRetrylimit
 *
 * wifi_setApRetrylimit(priv) (platform/intel) rejects a NULL priv (error line, RETURN_ERR, no vendor command) and otherwise sends the vendor command
 * SET_AP_RETRY_LIMIT with the 8-byte payload {4, 7} through wifi_drv_vendor_cmd (priv is only passed on, never dereferenced), returns the vendor result and, when it
 * is non-zero, logs "nl80211: sending _AP_RETRY_LIMIT failed: <res> (<strerror>)".  The suite crosses: priv NULL / the runner's fully POISONED slab / a dangling
 * pointer (0xdeadbeef); vendor result 0 / -1 / -2 / -5 / -12 / -22 / -95 (negative errno values, as the nl80211 layer returns them) / 1 / 5 / 22 / INT_MAX;
 * repeated calls; and a log slot that is empty / holds text / is almost full / is full.  Checks: the return value (the vendor result, RETURN_ERR for NULL),
 * the vendor command was sent exactly once per call with OUI_LTQ, the RETRY_LIMIT sub-command, the 8 payload bytes {4, 7}, length 8 and the same priv (never for NULL),
 * the guard slab is unchanged, and the log: the "couldn't find primary interface" line for NULL, the failure line with the result and the CORRECT error text
 * (strerror of the errno value, i.e. of -res for a negative result) when the vendor command failed, nothing otherwise.  Row layout: see hwr_irl_case_t.
 */
#include <limits.h>
#include "hwr_irl.h"

/* name, priv_mode (0 NULL, 1 poisoned slab, 2 dangling), vendor_ret, calls, prefill */
hwr_irl_case_t int_wifi_setApRetrylimit_suite[] = {
	{ "priv_null",                    0,    0,  1,   0 },
	{ "priv_null_vendor_would_fail",  0,  -22,  1,   0 },
	{ "priv_null_two_calls",          0,    0,  2,   0 },
	{ "priv_null_ten_calls",          0,    0, 10,   0 },
	{ "vendor_ok",                    1,    0,  1,   0 },
	{ "vendor_minus_1",               1,   -1,  1,   0 },
	{ "vendor_minus_2",               1,   -2,  1,   0 },
	{ "vendor_minus_5",               1,   -5,  1,   0 },
	{ "vendor_minus_12",              1,  -12,  1,   0 },
	{ "vendor_minus_22",              1,  -22,  1,   0 },
	{ "vendor_minus_95",              1,  -95,  1,   0 },
	{ "vendor_positive_1",            1,    1,  1,   0 },
	{ "vendor_positive_5",            1,    5,  1,   0 },
	{ "vendor_positive_22",           1,   22,  1,   0 },
	{ "vendor_int_max",               1, INT_MAX, 1, 0 },
	{ "priv_dangling_ok",             2,    0,  1,   0 },
	{ "priv_dangling_minus_22",       2,  -22,  1,   0 },
	{ "two_calls_ok",                 1,    0,  2,   0 },
	{ "two_calls_minus_22",           1,  -22,  2,   0 },
	{ "ten_calls_ok",                 1,    0, 10,   0 },
	{ "ten_calls_minus_5",            1,   -5, 10,   0 },
	{ "log_prefilled_1_minus_22",     1,  -22,  1,   1 },
	{ "log_prefilled_50_minus_5",     1,   -5,  1,  50 },
	{ "log_prefilled_100_minus_22",   1,  -22,  1, 100 },
	{ "log_almost_full_minus_22",     1,  -22,  1, 254 },
	{ "log_full_minus_22",            1,  -22,  1, 255 },
	{ "log_full_ok",                  1,    0,  1, 255 },
	{ "log_full_priv_null",           0,    0,  1, 255 },
	{ NULL, 0, 0, 0, 0 }
};

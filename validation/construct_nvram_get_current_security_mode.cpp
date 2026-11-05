/*
 * UNIT TEST (input constructor): construct_nvram_get_current_security_mode
 *
 * nvram_get_current_security_mode(security_mode, vap_index) (platform/banana-pi) is the platform's "read the security mode flag
 * from nvram" hook.  The banana-pi version logs and returns 0 without writing *security_mode, so the caller treats an
 * uninitialised enum as the nvram value.  The runner owns the enum in a slab (preset 0xA5, tail from byte 1 POISONED) and the
 * log slot; it calls the function and checks the contract this harness expects of a platform without nvram: -1 ("not
 * available") and *security_mode untouched.  Inputs crossed: vap_index 0 / 1 / 2 / 3 / -1 / INT_MAX / INT_MIN, security_mode
 * NULL, repeated calls, a prefilled / almost full / full log.  The unfixed function returns 0 in every row (finding).
 */
#include <limits.h>
#include "hwr_nsm.h"

/* name, vap_index, out_null, calls, prefill, expected_ret */
hwr_nsm_case_t nvram_get_current_security_mode_suite[] = {
	{ "vap_0",                     0,       0, 1,   0, -1 },
	{ "vap_1",                     1,       0, 1,   0, -1 },
	{ "vap_2",                     2,       0, 1,   0, -1 },
	{ "vap_3",                     3,       0, 1,   0, -1 },
	{ "vap_minus_1",              -1,       0, 1,   0, -1 },
	{ "vap_int_max",               INT_MAX, 0, 1,   0, -1 },
	{ "vap_int_min",               INT_MIN, 0, 1,   0, -1 },
	{ "out_null",                    0,       1, 1,   0, -1 },
	{ "out_null_vap_max",          INT_MAX, 1, 1,   0, -1 },
	{ "two_calls",                   1,       0, 2,   0, -1 },
	{ "log_prefilled_100",           0,       0, 1, 100, -1 },
	{ "log_almost_full",             0,       0, 1, 254, -1 },
	{ "log_full_nothing_written",    0,       0, 1, 255, -1 },
	{ NULL, 0, 0, 0, 0, 0 }
};

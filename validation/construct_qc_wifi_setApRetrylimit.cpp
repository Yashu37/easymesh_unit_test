/*
 * UNIT TEST (input constructor): construct_qc_wifi_setApRetrylimit
 *
 * wifi_setApRetrylimit(priv) (platform/qualcomm: platform_ext.c and platform_xer5.c hold identical code) returns RETURN_ERR with the error line "error couldn't
 * find primary interface" for priv == NULL; otherwise it calls wifi_setApRetryLimit(interface->vap_info.vap_index, 7), logs "AP_RETRY_LIMIT failed:<res>" when
 * that returns non-zero, and returns 0 in every case (see the handler header: the swallowed failure is a design note, not counted).  The suite crosses: priv
 * NULL / the runner's interface (fully POISONED except vap_index), vap_index 0 / 1 / 2 / 15 / 16 / 255 / 65535 / UINT_MAX, the stub result 0 / -1 / 1 / -22 /
 * INT_MAX / INT_MIN, repeated calls, and a log slot that is empty / holds text / is almost full / is full.  Checks: return value, wifi_setApRetryLimit called
 * once per call with (vap_index, 7) and never for NULL, the log lines, the interface bytes and guard slab.  Row layout: see hwr_qrl_case_t.
 */
#include <limits.h>
#include "hwr_qrl.h"

/* name, priv_mode (0 NULL, 1 interface), vap_index, limit_ret, calls, prefill */
hwr_qrl_case_t qc_wifi_setApRetrylimit_suite[] = {
	{ "vap_0_ok",                   1,          0,        0,  1,   0 },
	{ "vap_1_ok",                   1,          1,        0,  1,   0 },
	{ "vap_2_ok",                   1,          2,        0,  1,   0 },
	{ "vap_15_ok",                  1,         15,        0,  1,   0 },
	{ "vap_16_ok",                  1,         16,        0,  1,   0 },
	{ "vap_255_ok",                 1,        255,        0,  1,   0 },
	{ "vap_65535_ok",               1,      65535,        0,  1,   0 },
	{ "vap_uint_max_ok",            1,   UINT_MAX,        0,  1,   0 },
	{ "priv_null",                  0,          0,        0,  1,   0 },
	{ "priv_null_vendor_fail",      0,          3,       -1,  1,   0 },
	{ "priv_null_two_calls",        0,          0,        0,  2,   0 },
	{ "limit_fail_minus_1",         1,          0,       -1,  1,   0 },
	{ "limit_fail_plus_1",          1,          1,        1,  1,   0 },
	{ "limit_fail_minus_22",        1,          2,      -22,  1,   0 },
	{ "limit_fail_int_max",         1,         15,  INT_MAX,  1,   0 },
	{ "limit_fail_int_min",         1, UINT_MAX,    INT_MIN,  1,   0 },
	{ "two_calls_ok",               1,          1,        0,  2,   0 },
	{ "ten_calls_fail",             1,          4,       -5, 10,   0 },
	{ "log_prefilled_1_fail",       1,          0,       -1,  1,   1 },
	{ "log_prefilled_100_fail",     1,          0,       -1,  1, 100 },
	{ "log_almost_full_fail",       1,          0,       -1,  1, 254 },
	{ "log_full_fail",              1,          0,       -1,  1, 255 },
	{ "log_full_ok",                1,          0,        0,  1, 255 },
	{ "log_full_priv_null",         0,          0,        0,  1, 255 },
	{ NULL, 0, 0, 0, 0, 0 }
};

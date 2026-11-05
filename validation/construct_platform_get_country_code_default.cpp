/*
 * UNIT TEST (input constructor): construct_platform_get_country_code_default
 *
 * platform_get_country_code_default(code) (platform/banana-pi) logs and writes the default country code "US" (3 bytes with the NUL) into
 * the caller's buffer with strcpy, returns 0.  The callers in OneWifi (db/wifi_db.c: char country_code[4], db/wifi_db_apis.c:
 * COUNTRY_CODE_LEN buffer / char temp[32]) pass buffers of at least 4 bytes.  The runner owns the buffer in a slab whose tail behind the
 * 3 bytes the function may write is POISONED (so a longer write aborts), preset to zeros / 0xA5 / "DE".  Expected = the SAFE contract:
 * "US" and nothing else written, returns 0; NULL code -> -1.  Inputs crossed: buffer zeroed / 0xA5 / holding "DE" / "ABCD", repeated
 * calls, NULL code, log prefilled / almost full / full.  The NULL rows crash the unfixed function and run forked.
 */
#include "hwr_pcc.h"

/* name, prefill, null_code, calls, log_prefill, expected_ret, expected_code, forked */
hwr_pcc_case_t platform_get_country_code_default_suite[] = {
	{ "buffer_zeroed",                0, 0, 1,   0, 0, "US", 0 },
	{ "buffer_0xA5",                  1, 0, 1,   0, 0, "US", 0 },
	{ "buffer_holds_DE",              2, 0, 1,   0, 0, "US", 0 },
	{ "buffer_holds_ABCD",            3, 0, 1,   0, 0, "US", 0 },
	{ "two_calls_same_result",        2, 0, 2,   0, 0, "US", 0 },
	{ "log_prefilled_100",            0, 0, 1, 100, 0, "US", 0 },
	{ "log_almost_full",              0, 0, 1, 254, 0, "US", 0 },
	{ "log_full_nothing_written",     0, 0, 1, 255, 0, "US", 0 },
	{ "crash_code_null",              0, 1, 1,   0, -1, NULL, 1 },
	{ "crash_code_null_two_calls",    0, 1, 2,   0, -1, NULL, 1 },
	{ NULL, 0, 0, 0, 0, 0, NULL, 0 }
};

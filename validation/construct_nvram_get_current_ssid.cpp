/*
 * UNIT TEST (input constructor): construct_nvram_get_current_ssid
 *
 * nvram_get_current_ssid(l_ssid, vap_index) (platform/banana-pi) writes the default SSID "BPI_RDKB-AP<vap_index>" into the caller's buffer
 * with snprintf(l_ssid, BPI_LEN_16, ...) and returns 0 (the CONFIG_GENERIC_MLO build writes "BPI-RDKB-MLO-AP").  The only caller (OneWifi
 * db/wifi_db_apis.c:9852) passes bss_cfg->ssid (WIFI_AP_MAX_SSID_LEN = 32 bytes) with instance_number - 1 and retries after sleep(5) when the
 * result is not 0.  The runner owns the buffer in a slab whose tail behind the 16 bytes the function may write is POISONED (preset zeros /
 * 0xA5).  Expected = the SAFE contract: the name when it fits in 16 bytes (15 characters + NUL), otherwise -1 with the buffer untouched;
 * NULL l_ssid -> -1.  Inputs crossed: vap_index 0 / 1 / 7 / 15 / 99 / 999 / 9999 (fit, the longest fit is 15 characters), 10000 / 123456 /
 * INT_MAX (truncated), -1 (the caller's instance_number 0) / -999 (fit), -1000 / INT_MIN (truncated), buffer zeroed / 0xA5, repeated calls,
 * NULL l_ssid, log prefilled / almost full / full.  The NULL rows crash the unfixed function and run forked.
 */
#include <limits.h>
#include "hwr_ncs.h"

/* name, vap_index, prefill, null_ssid, calls, log_prefill, expected_ret, expected_ssid, forked */
hwr_ncs_case_t nvram_get_current_ssid_suite[] = {
	{ "vap_0",                       0, 0, 0, 1,   0, 0, "BPI_RDKB-AP0", 0 },
	{ "vap_1",                       1, 0, 0, 1,   0, 0, "BPI_RDKB-AP1", 0 },
	{ "vap_7",                       7, 0, 0, 1,   0, 0, "BPI_RDKB-AP7", 0 },
	{ "vap_15",                     15, 0, 0, 1,   0, 0, "BPI_RDKB-AP15", 0 },
	{ "vap_99",                     99, 0, 0, 1,   0, 0, "BPI_RDKB-AP99", 0 },
	{ "vap_999",                   999, 0, 0, 1,   0, 0, "BPI_RDKB-AP999", 0 },
	{ "vap_9999_longest_that_fits", 9999, 0, 0, 1,  0, 0, "BPI_RDKB-AP9999", 0 },
	{ "vap_minus_1",                -1, 0, 0, 1,   0, 0, "BPI_RDKB-AP-1", 0 },
	{ "vap_minus_999_fits",       -999, 0, 0, 1,   0, 0, "BPI_RDKB-AP-999", 0 },
	{ "vap_5_buf_0xA5",              5, 1, 0, 1,   0, 0, "BPI_RDKB-AP5", 0 },
	{ "vap_5_two_calls",             5, 0, 0, 2,   0, 0, "BPI_RDKB-AP5", 0 },
	{ "log_prefilled_100",           2, 0, 0, 1, 100, 0, "BPI_RDKB-AP2", 0 },
	{ "log_full_nothing_written",    2, 0, 0, 1, 255, 0, "BPI_RDKB-AP2", 0 },
	/* ---- does not fit in 16 bytes: must not be returned truncated as a success ---- */
	{ "vap_10000_truncated",     10000, 1, 0, 1,   0, -1, NULL, 0 },
	{ "vap_10005_truncated",     10005, 1, 0, 1,   0, -1, NULL, 0 },
	{ "vap_123456_truncated",   123456, 1, 0, 1,   0, -1, NULL, 0 },
	{ "vap_int_max_truncated",  INT_MAX, 1, 0, 1,  0, -1, NULL, 0 },
	{ "vap_minus_1000_truncated", -1000, 1, 0, 1,  0, -1, NULL, 0 },
	{ "vap_int_min_truncated",  INT_MIN, 1, 0, 1,  0, -1, NULL, 0 },
	/* ---- NULL l_ssid ---- */
	{ "crash_ssid_null",             0, 0, 1, 1,   0, -1, NULL, 1 },
	{ "crash_ssid_null_vap_15",     15, 0, 1, 1,   0, -1, NULL, 1 },
	{ NULL, 0, 0, 0, 0, 0, 0, NULL, 0 }
};

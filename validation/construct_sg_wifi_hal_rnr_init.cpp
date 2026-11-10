/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_rnr_init
 *
 * wifi_hal_rnr_init(radio_index, ssid).  Inputs crossed: radio_index 0 / 1 / 3 / out of range (4, 99, UINT_MAX) / no radio; ssid NULL / "" / 1 / 8 / 31 / 32 / 33 / 100 / 1000 chars (exact heap blocks);
 * the radio's rnr / rnr_enabled clean or holding old values.  Expected (CORRECT behaviour): no radio -> nothing touched; otherwise rnr cleared and rnr_enabled = false; for a non-empty ssid have_ssid = true,
 * ssid_crc = CRC-32 of the whole string, rnr.ssid = the first 31 chars, NUL-terminated; for NULL / "" have_ssid = false, ssid_crc 0 and an empty rnr.ssid.  Other radios untouched.  No crash case expected.
 */
#include "hwr_wri.h"
#include <limits.h>

/* name, radio_index, no_radio, ssid_mode, ssid_len, dirty, last */
hwr_wri_case_t sg_wifi_hal_rnr_init_suite[] = {
	{ "no_radio",              0, 1, 2,  8, 1, 0 },
	{ "radio_index_4",         4, 0, 2,  8, 1, 0 },
	{ "radio_index_99",       99, 0, 0,  0, 1, 0 },
	{ "radio_index_uint_max", UINT_MAX, 0, 2, 8, 1, 0 },
	{ "radio_0",               0, 0, 2,  8, 0, 0 },
	{ "radio_1",               1, 0, 2,  8, 0, 0 },
	{ "radio_3",               3, 0, 2,  8, 0, 0 },
	{ "ssid_null",             0, 0, 0,  0, 0, 0 },
	{ "ssid_null_dirty",       1, 0, 0,  0, 1, 0 },
	{ "ssid_empty",            0, 0, 1,  0, 0, 0 },
	{ "ssid_empty_dirty",      2, 0, 1,  0, 1, 0 },
	{ "ssid_1_char",           0, 0, 2,  1, 0, 0 },
	{ "ssid_8_chars",          0, 0, 2,  8, 0, 0 },
	{ "ssid_8_chars_dirty",    1, 0, 2,  8, 1, 0 },
	{ "ssid_30_chars",         0, 0, 2, 30, 0, 0 },
	{ "ssid_31_chars",         0, 0, 2, 31, 0, 0 },
	{ "ssid_31_chars_dirty",   2, 0, 2, 31, 1, 0 },
	{ "ssid_32_chars",         0, 0, 2, 32, 0, 0 },
	{ "ssid_32_chars_dirty",   3, 0, 2, 32, 1, 0 },
	{ "ssid_33_chars",         0, 0, 2, 33, 0, 0 },
	{ "ssid_64_chars",         1, 0, 2, 64, 1, 0 },
	{ "ssid_100_chars",        0, 0, 2,100, 0, 0 },
	{ "ssid_1000_chars",       0, 0, 2,1000,1, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};

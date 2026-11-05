/*
 * UNIT TEST (input constructor): construct_platform_get_wps_pin_default
 *
 * platform_get_wps_pin_default(pin) (platform/banana-pi) reads the "wps_pin" value of /nvram/wifi_defaults.txt into the caller's buffer
 * (wifi_nvram_defaultRead) and returns 0.  The callers in OneWifi (db/wifi_db.c, db/wifi_db_apis.c, dml/dml_webconfig/dml_onewifi_api.c)
 * pass zeroed 128-byte buffers, treat 0 as "pin read" and copy it with strcpy() into the HAL's WPS pin field, which is
 * WIFI_AP_MAX_WPSPIN_LEN = 9 bytes (8 characters + NUL).  The runner owns the pin buffer in a slab whose tail behind 128 bytes it POISONS
 * (preset zeros / 0xA5); wifi_nvram_defaultRead is a stub (see the handler).  Expected = the SAFE contract: a pin is returned only when
 * the nvram has 1..8 characters for it, otherwise -1 and the buffer untouched; NULL pin -> -1.  Inputs crossed: 4 / 7 / 8 digit pins
 * (fit), 1 character, 9 / 10 / 20 / 127 characters (do not fit the HAL field), an empty value, the key missing (nvram -1), the key missing
 * with an uninitialised caller buffer, NULL pin, a 128-character value (needs 129 bytes: the buffer overflows; cannot be produced by
 * the real reader, kept as hardening).  The rows that crash the unfixed function run forked.
 */
#include "hwr_pwp.h"

hwr_pwp_rec_t hwr_pwp_rec;
extern "C" int hwr_pwp_nvram(char *in, char *out)
{
	hwr_pwp_rec.calls++;
	snprintf(hwr_pwp_rec.key, sizeof(hwr_pwp_rec.key), "%s", in);
	if (hwr_pwp_rec.nvram_ret) return -1;
	strncpy(out, hwr_pwp_rec.nvram_val, strlen(hwr_pwp_rec.nvram_val) + 1);   /* wifi_nvram_defaultRead: strncpy(out,position,strlen(position)+1) */
	return 0;
}

#define L10  "0123456789"
#define L100 L10 L10 L10 L10 L10 L10 L10 L10 L10 L10
#define L127 L100 L10 L10 "0123456"
#define L128 L100 L10 L10 "01234567"
/* name, nvram_ret, nvram_val, prefill, null_pin, expected_ret, expected_pin, forked */
hwr_pwp_case_t platform_get_wps_pin_default_suite[] = {
	{ "pin_8_digits",                0, "12345670", 0, 0, 0, "12345670", 0 },
	{ "pin_4_digits",                0, "1234",     0, 0, 0, "1234", 0 },
	{ "pin_7_digits",                0, "1234567",  0, 0, 0, "1234567", 0 },
	{ "pin_1_char",                  0, "7",        0, 0, 0, "7", 0 },
	{ "pin_8_chars_not_digits",      0, "abcdefgh", 0, 0, 0, "abcdefgh", 0 },
	{ "pin_9_chars_too_long",        0, "123456789", 0, 0, -1, NULL, 0 },
	{ "pin_10_chars_too_long",       0, "1234567890", 0, 0, -1, NULL, 0 },
	{ "pin_20_chars_too_long",       0, "12345678901234567890", 0, 0, -1, NULL, 0 },
	{ "pin_127_chars_too_long",      0, L127, 0, 0, -1, NULL, 0 },
	{ "value_empty",                 0, "", 0, 0, -1, NULL, 0 },
	{ "key_missing_buf_zeroed",     -1, "", 0, 0, -1, NULL, 0 },
	{ "key_missing_buf_uninit",     -1, "", 1, 0, -1, NULL, 0 },
	{ "pin_ok_buf_uninit",           0, "12345670", 1, 0, 0, "12345670", 0 },
	{ "crash_pin_128_chars_overflow", 0, L128, 0, 0, -1, NULL, 1 },
	{ "crash_pin_null_key_found",    0, "12345670", 0, 1, -1, NULL, 1 },
	{ "pin_null_key_missing", -1, "", 0, 1, -1, NULL, 1 },
	{ NULL, 0, NULL, 0, 0, 0, NULL, 0 }
};

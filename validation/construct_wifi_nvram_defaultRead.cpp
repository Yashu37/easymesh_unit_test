/*
 * UNIT TEST (input constructor): construct_wifi_nvram_defaultRead
 *
 * wifi_nvram_defaultRead(in, out) (platform/banana-pi) returns the value of the key `in` from
 * /nvram/wifi_defaults.txt ("key=value" lines) by running `grep '<in>=' /nvram/wifi_defaults.txt` and copying what follows
 * the first '=' of the first output line (up to the newline, at most 127 bytes) into `out`; -1 when there is no such
 * line.  The callers (platform_get_keypassphrase_default, platform_get_wps_pin_default, platform_pre_create_vap...)
 * only pass string literals as the key and fixed-size buffers (e.g. char output_val[BPI_LEN_32]) as `out`.
 *
 * The suite is a table of file contents, keys and output buffer sizes; the runner (wifi_nvram_defaultRead_test.cpp)
 * writes the file to a temporary directory (the command runs in a REAL shell with a REAL grep, see the handler), owns
 * the key and the output buffer in slabs whose tails it POISONS (everything behind the caller's buffer of `cap` bytes),
 * calls the function, unpoisons and checks the result, the output, and that no injected command ran (marker file).
 * Inputs crossed: keys found at the first / last / middle line, without a trailing newline, duplicates (first wins),
 * values containing '=' / spaces / empty, a value that exactly fits the buffer, missing key / empty file / missing
 * file / empty key, lines whose key only CONTAINS the wanted key (prefix "x", "#", "old_", the key inside another
 * line's value, a regex '.' in the key), keys with a quote that breaks out of the shell quoting (and `$()` / backticks
 * inside the quotes as controls), NULL key, NULL out, values longer than the caller's buffer (33 / 40 bytes into 32,
 * into 1 and into 0), and lines longer than the 127-byte read buffer.
 * Expected result is the SAFE contract (exact key match, no shell, output bounded by its size, nothing written on
 * failure), so a FAIL is a finding.  Rows that crash the unfixed function run forked so the ASan report is visible
 * but the run continues.
 */
#include <limits.h>
#include "hwr_nvr.h"

char hwr_nvr_path[256];

static void rewrite_path(const char *cmd, char *tmp, size_t cap)
{
	const char *real = "/nvram/wifi_defaults.txt";
	const char *p = strstr(cmd, real);

	if (!p) { snprintf(tmp, cap, "%s", cmd); return; }
	snprintf(tmp, cap, "%.*s%s%s", (int)(p - cmd), cmd, hwr_nvr_path, p + strlen(real));
}
extern "C" int hwr_nvr_syscmd(char *cmd, char *retBuf, int retBufSize)
{
	char tmp[4096];
	rewrite_path(cmd, tmp, sizeof(tmp));
	return hwr_nvr_real_syscmd(tmp, retBuf, retBufSize);
}
extern "C" FILE *hwr_nvr_fopen(const char *path, const char *mode)
{
	return fopen(strcmp(path, "/nvram/wifi_defaults.txt") == 0 ? hwr_nvr_path : path, mode);
}

#define V40 "0123456789012345678901234567890123456789"
#define V31 "0123456789012345678901234567890"
#define V32 "01234567890123456789012345678901"
#define L125 "01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234"
#define L126 L125 "9"
#define L182 V40 V40 V40 V40 "01234567890123456789012345678901234567890123456789012345678901"
/* name, file, key, null_out, cap, expected_ret, expected_out, marker_forbidden, forked */
hwr_nvr_case_t wifi_nvram_defaultRead_suite[] = {
	/* ---- found ---- */
	{ "found_simple",                   "bpi_wifi_password=secret123\n", "bpi_wifi_password", 0, 64, 0, "secret123", 0, 0 },
	{ "found_last_line_no_newline",     "a=1\nwps_pin=12345678", "wps_pin", 0, 16, 0, "12345678", 0, 0 },
	{ "found_among_other_keys",         "a=1\nb=2\nwps_pin=777\nc=3\n", "wps_pin", 0, 16, 0, "777", 0, 0 },
	{ "found_first_of_duplicates",      "wps_pin=1\nwps_pin=2\n", "wps_pin", 0, 16, 0, "1", 0, 0 },
	{ "value_contains_equals",          "wps_pin=12=34\n", "wps_pin", 0, 16, 0, "12=34", 0, 0 },
	{ "value_empty",                    "wps_pin=\n", "wps_pin", 0, 16, 0, "", 0, 0 },
	{ "value_with_spaces",              "bpi_wifi_password=my pass word\n", "bpi_wifi_password", 0, 64, 0, "my pass word", 0, 0 },
	{ "value_ip_address",               "radius_s_ip=10.0.0.1\n", "radius_s_ip", 0, 64, 0, "10.0.0.1", 0, 0 },
	{ "value_31_chars_fits_cap_32",     "radius_s_port=" V31 "\n", "radius_s_port", 0, 32, 0, V31, 0, 0 },
	{ "cap_1_empty_value_fits",         "wps_pin=\n", "wps_pin", 0, 1, 0, "", 0, 0 },
	{ "value_125_chars_line_127",       "k=" L125 "\n", "k", 0, 256, 0, L125, 0, 0 },
	/* ---- not found: -1, output untouched ---- */
	{ "key_missing",                    "a=1\n", "wps_pin", 0, 16, -1, NULL, 0, 0 },
	{ "file_empty",                     "", "wps_pin", 0, 16, -1, NULL, 0, 0 },
	{ "file_missing",                   NULL, "wps_pin", 0, 16, -1, NULL, 0, 0 },
	{ "key_without_equals_sign",        "wps_pin\n", "wps_pin", 0, 16, -1, NULL, 0, 0 },
	{ "key_case_differs",               "wps_pin=1\n", "WPS_PIN", 0, 16, -1, NULL, 0, 0 },
	{ "key_empty_string",               "a=1\nb=2\n", "", 0, 16, -1, NULL, 0, 0 },
	/* ---- a line only CONTAINING "key=" is not the key ---- */
	{ "only_prefixed_key_present",      "xwps_pin=111\n", "wps_pin", 0, 16, -1, NULL, 0, 0 },
	{ "prefixed_key_before_real_one",   "xwps_pin=111\nwps_pin=222\n", "wps_pin", 0, 16, 0, "222", 0, 0 },
	{ "commented_key_before_real_one",  "#wps_pin=111\nwps_pin=222\n", "wps_pin", 0, 16, 0, "222", 0, 0 },
	{ "old_password_before_real_one",   "old_bpi_wifi_password=aaa\nbpi_wifi_password=bbb\n", "bpi_wifi_password", 0, 64, 0, "bbb", 0, 0 },
	{ "key_inside_value_of_other_line", "note=use wps_pin=9\nwps_pin=5\n", "wps_pin", 0, 16, 0, "5", 0, 0 },
	{ "regex_dot_in_key_matches_other", "wpsXpin=1\n", "wps.pin", 0, 16, -1, NULL, 0, 0 },
	/* ---- the key is put into a shell command ---- */
	{ "inject_quote_breakout_runs_command", "x=1\n", "x' /dev/null; touch %M; echo '", 0, 64, -1, NULL, 1, 0 },
	{ "control_dollar_paren_in_quotes", "x=1\n", "$(touch %M)", 0, 64, -1, NULL, 1, 0 },
	{ "control_backticks_in_quotes",    "x=1\n", "`touch %M`", 0, 64, -1, NULL, 1, 0 },
	/* ---- NULL arguments ---- */
	{ "key_null",                       "a=1\n", NULL, 0, 16, -1, NULL, 0, 0 },
	{ "out_null_key_missing",           "a=1\n", "wps_pin", 1, 16, -1, NULL, 0, 0 },
	{ "crash_out_null_key_found",       "wps_pin=123\n", "wps_pin", 1, 16, -1, NULL, 0, 1 },
	{ "crash_out_null_empty_value",     "wps_pin=\n", "wps_pin", 1, 16, -1, NULL, 0, 1 },
	/* ---- value longer than the caller's buffer (no size is passed to the unfixed function) ---- */
	{ "crash_value_40_chars_cap_32",    "radius_s_port=" V40 "\n", "radius_s_port", 0, 32, -1, NULL, 0, 1 },
	{ "crash_value_32_chars_cap_32",    "radius_s_port=" V32 "\n", "radius_s_port", 0, 32, -1, NULL, 0, 1 },
	{ "crash_value_3_chars_cap_1",      "wps_pin=123\n", "wps_pin", 0, 1, -1, NULL, 0, 1 },
	{ "crash_value_3_chars_cap_0",      "wps_pin=123\n", "wps_pin", 0, 0, -1, NULL, 0, 1 },
	/* ---- lines longer than the 127-byte read buffer are truncated silently ---- */
	{ "line_200_chars_not_truncated",   "bpi_wifi_password=" L182 "\n", "bpi_wifi_password", 0, 256, -1, NULL, 0, 0 },
	{ "line_128_chars_not_truncated",   "k=" L126 "\n", "k", 0, 256, -1, NULL, 0, 0 },
	{ NULL, NULL, NULL, 0, 0, 0, NULL, 0, 0 }
};

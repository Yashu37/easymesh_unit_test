/*
 * UNIT TEST (input constructor): construct_rp_wifi_nvram_defaultRead
 *
 * wifi_nvram_defaultRead(in, out) (platform/raspberry-pi and platform/wifi-emulator, identical code) formats the command "grep '<in>=' /nvram/wifi_defaults.txt" with an
 * UNBOUNDED sprintf into char cmd[1024], runs it, and copies the text after the first '=' of the first output line into out (-1 when the output is empty, has no '=',
 * or the command fails).  _syscmd is a stub (records the command, returns the case's canned reply / result).  The suite crosses: the reply (a normal "key=value", an
 * empty value, a value containing '=', a reply without trailing newline, several lines, an empty reply, a reply without '='), the command result 0 / -1, key lengths
 * 0 / 1 / 7 / 100 / 500 / 990 (the longest key that still fits: the command is checked byte for byte) and the output slot (an exact-size slab whose surrounding bytes are
 * POISONED).  Rows named invalid_* use keys of 991 .. 5000 characters: the command no longer fits into cmd[1024] and sprintf overflows the stack buffer (expected
 * safe behaviour: the command is cut at 1023 bytes and the function carries on); they run LAST.  Row: name, key_len (-1: key_text), key_text, reply, syscmd_ret,
 * out_mode, calls, expected_ret, expected_out, last.
 */
#include "hwr_nvd.h"

/* name, key_len, key_text, reply, syscmd_ret, out_mode (1: exact-size slab), calls, expected_ret, expected_out, last */
hwr_nvd_case_t rp_wifi_nvram_defaultRead_suite[] = {
	{ "key_wps_pin_value",             -1, "wps_pin",  "wps_pin=12345678\n",         0, 1, 1,  0, "12345678", 0 },
	{ "key_bpi_wifi_password",         -1, "bpi_wifi_password", "bpi_wifi_password=Secret99\n", 0, 1, 1, 0, "Secret99", 0 },
	{ "value_empty",                   -1, "ssid",     "ssid=\n",                    0, 1, 1,  0, "",         0 },
	{ "value_one_char",                -1, "ssid",     "ssid=x\n",                   0, 1, 1,  0, "x",        0 },
	{ "value_contains_equals",         -1, "pass",     "pass=a=b=c\n",               0, 1, 1,  0, "a=b=c",    0 },
	{ "value_with_spaces",             -1, "ssid",     "ssid=My Home WiFi\n",        0, 1, 1,  0, "My Home WiFi", 0 },
	{ "reply_without_newline",         -1, "ssid",     "ssid=nonl",                  0, 1, 1,  0, "nonl",     0 },
	{ "reply_two_lines_first_used",    -1, "ssid",     "ssid=first\nssid=second\n",  0, 1, 1,  0, "first",    0 },
	{ "reply_other_key_returned",      -1, "ssid",     "xssid=wrong\n",              0, 1, 1,  0, "wrong",    0 },
	{ "reply_empty",                   -1, "ssid",     NULL,                         0, 1, 1, -1, NULL,       0 },
	{ "reply_without_equals",          -1, "ssid",     "garbage line\n",             0, 1, 1, -1, NULL,       0 },
	{ "reply_only_newline",            -1, "ssid",     "\n",                         0, 1, 1, -1, NULL,       0 },
	{ "syscmd_fails",                  -1, "ssid",     "ssid=ignored\n",            -1, 1, 1, -1, NULL,       0 },
	{ "syscmd_fails_empty_reply",      -1, "ssid",     NULL,                        -1, 1, 1, -1, NULL,       0 },
	{ "key_empty",                      0, NULL,       "=v\n",                       0, 1, 1,  0, "v",        0 },
	{ "key_len_1",                      1, NULL,       "k=v\n",                      0, 1, 1,  0, "v",        0 },
	{ "key_len_7",                      7, NULL,       "kkkkkkk=v7\n",               0, 1, 1,  0, "v7",       0 },
	{ "key_len_100",                  100, NULL,       "k=v100\n",                   0, 1, 1,  0, "v100",     0 },
	{ "key_len_500",                  500, NULL,       "k=v500\n",                   0, 1, 1,  0, "v500",     0 },
	{ "key_len_900",                  900, NULL,       "k=v900\n",                   0, 1, 1,  0, "v900",     0 },
	{ "key_len_990_longest_that_fits",990, NULL,       "k=v990\n",                   0, 1, 1,  0, "v990",     0 },
	{ "two_calls",                     -1, "ssid",     "ssid=abc\n",                 0, 1, 2,  0, "abc",      0 },
	{ "ten_calls_fail",                -1, "ssid",     NULL,                         0, 1, 10, -1, NULL,      0 },
	/* ---- key too long for cmd[1024]: sprintf overflows the stack buffer (run last) ---- */
	{ "invalid_key_len_991",          991, NULL,       "k=v\n",                      0, 1, 1,  0, "v",        1 },
	{ "invalid_key_len_1000",        1000, NULL,       "k=v\n",                      0, 1, 1,  0, "v",        1 },
	{ "invalid_key_len_1023",        1023, NULL,       "k=v\n",                      0, 1, 1,  0, "v",        1 },
	{ "invalid_key_len_1024",        1024, NULL,       "k=v\n",                      0, 1, 1,  0, "v",        1 },
	{ "invalid_key_len_2000",        2000, NULL,       NULL,                         0, 1, 1, -1, NULL,       1 },
	{ "invalid_key_len_4000",        4000, NULL,       "k=v\n",                      0, 1, 1,  0, "v",        1 },
	{ NULL, 0, NULL, NULL, 0, 0, 0, 0, NULL, 0 }
};

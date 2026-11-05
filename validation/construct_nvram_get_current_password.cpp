/*
 * UNIT TEST (input constructor): construct_nvram_get_current_password
 *
 * nvram_get_current_password(l_password, vap_index) (platform/banana-pi) reads "bpi_wifi_password" of /nvram/wifi_defaults.txt into the
 * caller's buffer (wifi_nvram_defaultRead) and returns 0.  The only caller (OneWifi db/wifi_db_apis.c:9884) passes
 * bss_cfg->security.u.key.key (256 bytes) and, for private vaps, retries after sleep(5) when the result is not 0.  The runner owns the buffer
 * in a slab whose tail behind 256 bytes it POISONS (preset zeros / 0xA5 / "old"); wifi_nvram_defaultRead is a stub (see the handler).
 * Expected = the SAFE contract: 0 and the password only when a non-empty password was read, otherwise -1 and the buffer untouched (the
 * caller then retries); NULL l_password -> -1.  Inputs crossed: 8 / 12 / 63 / 127-char passwords, an empty value, the key missing, vap_index
 * 0 / 1 / 3 / -1 / INT_MAX (unused), buffer zeroed / 0xA5 / holding "old", the retry (first call fails, second succeeds; first succeeds,
 * second fails), NULL l_password.  The NULL rows crash the unfixed function and run forked.
 */
#include <limits.h>
#include "hwr_ncp.h"

hwr_ncp_rec_t hwr_ncp_rec;
extern "C" int hwr_ncp_nvram(char *in, char *out)
{
	int k = hwr_ncp_rec.calls < 2 ? hwr_ncp_rec.calls : 1;

	hwr_ncp_rec.calls++;
	snprintf(hwr_ncp_rec.key, sizeof(hwr_ncp_rec.key), "%s", in);
	if (hwr_ncp_rec.ret[k]) return -1;
	strncpy(out, hwr_ncp_rec.val[k], strlen(hwr_ncp_rec.val[k]) + 1);   /* wifi_nvram_defaultRead: strncpy(out,position,strlen(position)+1) */
	return 0;
}

#define L10  "0123456789"
#define L63  L10 L10 L10 L10 L10 L10 "012"
#define L127 L10 L10 L10 L10 L10 L10 L10 L10 L10 L10 L10 L10 "0123456"
/* name, vap_index, nvram_ret, nvram_val, nvram_ret2, nvram_val2, prefill, null_pw, calls, expected_ret, expected_pw, forked */
hwr_ncp_case_t nvram_get_current_password_suite[] = {
	{ "password_8_chars",            0, 0, "12345678", 0, "", 0, 0, 1, 0, "12345678", 0 },
	{ "password_12_chars",           1, 0, "MyPassword12", 0, "", 0, 0, 1, 0, "MyPassword12", 0 },
	{ "password_63_chars",           0, 0, L63, 0, "", 0, 0, 1, 0, L63, 0 },
	{ "password_127_chars",          0, 0, L127, 0, "", 0, 0, 1, 0, L127, 0 },
	{ "password_with_spaces",        0, 0, "my pass phrase", 0, "", 0, 0, 1, 0, "my pass phrase", 0 },
	{ "password_overwrites_old",     0, 0, "newpass1", 0, "", 2, 0, 1, 0, "newpass1", 0 },
	{ "password_buf_uninit_0xA5",    0, 0, "12345678", 0, "", 1, 0, 1, 0, "12345678", 0 },
	{ "vap_index_3",                 3, 0, "12345678", 0, "", 0, 0, 1, 0, "12345678", 0 },
	{ "vap_index_minus_1",          -1, 0, "12345678", 0, "", 0, 0, 1, 0, "12345678", 0 },
	{ "vap_index_int_max",     INT_MAX, 0, "12345678", 0, "", 0, 0, 1, 0, "12345678", 0 },
	/* ---- not read: the caller must see -1 and keep its buffer ---- */
	{ "key_missing_buf_zeroed",      0, -1, "", 0, "", 0, 0, 1, -1, NULL, 0 },
	{ "key_missing_buf_0xA5",        0, -1, "", 0, "", 1, 0, 1, -1, NULL, 0 },
	{ "key_missing_buf_holds_old",   0, -1, "", 0, "", 2, 0, 1, -1, NULL, 0 },
	{ "value_empty_buf_zeroed",      0, 0, "", 0, "", 0, 0, 1, -1, NULL, 0 },
	{ "value_empty_buf_holds_old",   0, 0, "", 0, "", 2, 0, 1, -1, NULL, 0 },
	/* ---- the caller's retry after a failed read ---- */
	{ "retry_first_fails_second_ok", 0, -1, "", 0, "retrypw12", 0, 0, 2, 0, "retrypw12", 0 },
	{ "first_ok_second_fails_keeps", 0, 0, "firstpw12", -1, "", 0, 0, 2, -1, "firstpw12", 0 },
	/* ---- NULL l_password ---- */
	{ "crash_password_null_key_found", 0, 0, "12345678", 0, "", 0, 1, 1, -1, NULL, 1 },
	{ "password_null_key_missing",   0, -1, "", 0, "", 0, 1, 1, -1, NULL, 1 },
	{ NULL, 0, 0, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0 }
};

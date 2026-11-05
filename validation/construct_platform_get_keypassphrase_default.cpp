/*
 * UNIT TEST (input constructor): construct_platform_get_keypassphrase_default
 *
 * platform_get_keypassphrase_default(password, vap_index) (platform/banana-pi) returns the default Wi-Fi passphrase: for the mesh STA
 * vap it first tries "Backhaul_KeyPassphrase" of /nvram/EasymeshCfg.json (json_parse_backhaul_keypassphrase), then the nvram default
 * "bpi_wifi_password" (wifi_nvram_defaultRead), and if that is empty the fixed INVALID_KEY "12345678"; it always returns 0.
 * The callers (OneWifi) pass 128-byte zeroed buffers (wifi_db_apis.c, wifi_ctrl_webconfig.c, wifi_multidoc_webconfig.c) and one
 * 64-byte zeroed buffer (wifi_dml_cb.c).  The runner owns the password buffer in a slab whose tail behind the caller's buffer (128 / 64
 * bytes) is POISONED; the collaborators are stubs with controllable results (see the handler).  Expected = the SAFE contract: nothing
 * is written behind the 128 bytes, a failed / empty / oversized source falls through to the next one and finally to INVALID_KEY,
 * NULL password -> -1.  Inputs crossed: mesh STA vs other vap_index (the JSON source must only be used for the mesh STA index), JSON
 * ok / failing / empty / 127-char / 128-char value, nvram ok / failing / empty / 127-char / 128-char value, caller buffer zeroed / uninitialised
 * (0xA5, no NUL) / holding "junk", 64-byte caller buffer, NULL password, extreme vap_index.  The rows that crash the unfixed function
 * run forked.
 */
#include <limits.h>
#include "hwr_pgk.h"

hwr_pgk_rec_t hwr_pgk_rec;
extern "C" BOOL hwr_pgk_is_mesh_sta(UINT ap_index) { hwr_pgk_rec.mesh_calls++; hwr_pgk_rec.last_vap_index = (int)ap_index; return (int)ap_index == hwr_pgk_rec.mesh_sta_index; }
extern "C" int hwr_pgk_json(char *out)
{
	hwr_pgk_rec.json_calls++;
	if (hwr_pgk_rec.json_ret) return hwr_pgk_rec.json_ret;
	strncpy(out, hwr_pgk_rec.json_val, 129);      /* json_parse_string: strncpy(val, str, len); val[len-1] = '\0'; len = MAX_KEYPASSPHRASE_LEN */
	out[129 - 1] = '\0';
	return 0;
}
extern "C" int hwr_pgk_nvram(char *in, char *out)
{
	(void)in;
	hwr_pgk_rec.nvram_calls++;
	if (hwr_pgk_rec.nvram_ret) return -1;
	strncpy(out, hwr_pgk_rec.nvram_val, strlen(hwr_pgk_rec.nvram_val) + 1);   /* wifi_nvram_defaultRead: strncpy(out,position,strlen(position)+1) */
	return 0;
}

#define L10  "0123456789"
#define L100 L10 L10 L10 L10 L10 L10 L10 L10 L10 L10
#define L63  L10 L10 L10 L10 L10 L10 "012"
#define L127 L100 L10 L10 "0123456"
#define L128 L100 L10 L10 "01234567"
/* name, vap_index, mesh_sta_index, json_ret, json_val, nvram_ret, nvram_val, prefill, null_pw, expected_ret, expected_pw, exp_json_calls, exp_nvram_calls, expect_fallback_log, forked */
hwr_pgk_case_t platform_get_keypassphrase_default_suite[] = {
	/* ---- mesh STA: JSON source ---- */
	{ "mesh_sta_json_ok",                  3, 3, 0, "secret123", 0, "nv-pass", 0, 0, 0, "secret123", 1, 0, 0, 1 },
	{ "mesh_sta_json_ok_63_chars",         3, 3, 0, L63, 0, "nv-pass", 0, 0, 0, L63, 1, 0, 0, 1 },
	{ "mesh_sta_json_ok_127_chars",        3, 3, 0, L127, 0, "nv-pass", 0, 0, 0, L127, 1, 0, 0, 1 },
	{ "mesh_sta_json_128_chars_no_fit",    3, 3, 0, L128, 0, "nv-pass", 0, 0, 0, "nv-pass", 1, 1, 0, 1 },
	{ "mesh_sta_json_empty_value",         3, 3, 0, "", 0, "nv-pass", 0, 0, 0, "nv-pass", 1, 1, 0, 1 },
	{ "mesh_sta_json_fails_nvram_ok",      3, 3, -1, "", 0, "nv-pass", 0, 0, 0, "nv-pass", 1, 1, 0, 0 },
	{ "mesh_sta_json_fails_nvram_fails",   3, 3, -1, "", -1, "", 0, 0, 0, "12345678", 1, 1, 1, 0 },
	{ "mesh_sta_index_0",                  0, 0, 0, "zero", 0, "nv", 0, 0, 0, "zero", 1, 0, 0, 1 },
	{ "mesh_sta_index_15",                15, 15, 0, "fifteen", 0, "nv", 0, 0, 0, "fifteen", 1, 0, 0, 1 },
	{ "mesh_sta_buffer_64_json_ok",        3, 3, 0, "secret123", 0, "nv", 3, 0, 0, "secret123", 1, 0, 0, 1 },
	/* ---- other vap: nvram source only ---- */
	{ "other_vap_nvram_ok",                1, 3, 0, "json", 0, "nv-pass", 0, 0, 0, "nv-pass", 0, 1, 0, 0 },
	{ "other_vap_nvram_127_chars",         1, 3, 0, "json", 0, L127, 0, 0, 0, L127, 0, 1, 0, 0 },
	{ "crash_other_vap_nvram_128_chars_no_fit", 1, -2, 0, "json", 0, L128, 0, 0, 0, "12345678", 0, 1, 1, 1 },
	{ "other_vap_nvram_empty_fallback",    1, -2, 0, "json", 0, "", 0, 0, 0, "12345678", 0, 1, 1, 0 },
	{ "other_vap_nvram_fails_buf_zeroed",  1, -2, 0, "json", -1, "", 0, 0, 0, "12345678", 0, 1, 1, 0 },
	{ "other_vap_no_mesh_sta_at_all",      7, -2, 0, "json", 0, "nv-pass", 0, 0, 0, "nv-pass", 0, 1, 0, 0 },
	{ "vap_index_minus_1",                -1, -2, 0, "json", 0, "nv-pass", 0, 0, 0, "nv-pass", 0, 1, 0, 0 },
	{ "vap_index_int_max",           INT_MAX, -2, 0, "json", 0, "nv-pass", 0, 0, 0, "nv-pass", 0, 1, 0, 0 },
	{ "mesh_sta_index_differs_from_vap",   2, 3, 0, "json", 0, "nv-pass", 0, 0, 0, "nv-pass", 0, 1, 0, 0 },
	/* ---- nvram failure ignored: the caller's buffer is measured / returned ---- */
	{ "crash_nvram_fails_buf_uninit",      1, -2, 0, "json", -1, "", 1, 0, 0, "12345678", 0, 1, 1, 1 },
	{ "nvram_fails_buf_holds_junk",        1, -2, 0, "json", -1, "", 2, 0, 0, "12345678", 0, 1, 1, 0 },
	{ "crash_nvram_fails_mesh_json_fails_buf_uninit", 3, 3, -1, "", -1, "", 1, 0, 0, "12345678", 1, 1, 1, 1 },
	/* ---- NULL password ---- */
	{ "crash_password_null_other_vap",     1, -2, 0, "json", 0, "nv-pass", 0, 1, -1, NULL, 0, 0, 0, 1 },
	{ "crash_password_null_mesh_sta",      3, 3, 0, "secret123", 0, "nv-pass", 0, 1, -1, NULL, 0, 0, 0, 1 },
	{ NULL, 0, 0, 0, NULL, 0, NULL, 0, 0, 0, NULL, 0, 0, 0, 0 }
};

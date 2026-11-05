/*
 * UNIT TEST (input constructor): construct_platform_get_ssid_default
 *
 * platform_get_ssid_default(ssid, vap_index) (platform/banana-pi, no CONFIG_GENERIC_MLO) returns the default SSID: for the mesh STA vap
 * "Backhaul_SSID" of /nvram/EasymeshCfg.json (json_parse_backhaul_ssid), otherwise "BPI_RDKB-AP<vap_index>-<serial>" where <serial> is the
 * last 7 bytes of /nvram/serial_number.txt up to the first newline (the file may be missing: empty serial; shorter than 7 bytes: -1).
 * The callers (OneWifi) pass 128-byte buffers; the HAL's SSID size is 33 (32 + NUL), which is the contract used here: the runner owns the
 * ssid buffer in a slab whose tail from byte 33 it POISONS (preset 0xA5).  The serial file is REAL (temporary file).  Expected = the SAFE
 * contract: -1 leaves ssid untouched, nothing is written behind 33 bytes, the SSID holds no control characters from the serial file,
 * NULL ssid -> -1.  Inputs crossed: mesh STA vs other vap (the JSON source only for the mesh STA index), JSON ok / 32 chars / failing;
 * serial files of 7 / 8 / 10 / 12 bytes with and without newline, CRLF, newline at the start of the last 7 bytes, embedded NUL, file
 * missing / empty / shorter than 7 bytes; vap_index 0 / 1 / 15 / 99 / -1 / INT_MAX / INT_MIN; NULL ssid.  The rows that crash the unfixed
 * function run forked.
 */
#include <limits.h>
#include "hwr_psd.h"

char hwr_psd_path[256];
hwr_psd_rec_t hwr_psd_rec;
extern "C" FILE *hwr_psd_fopen(const char *path, const char *mode)
{
	return fopen(strcmp(path, "/nvram/serial_number.txt") == 0 ? hwr_psd_path : path, mode);
}
extern "C" BOOL hwr_psd_is_mesh_sta(UINT ap_index) { return (int)ap_index == hwr_psd_rec.mesh_sta_index; }
extern "C" int hwr_psd_json(char *out)
{
	hwr_psd_rec.json_calls++;
	if (hwr_psd_rec.json_ret) return hwr_psd_rec.json_ret;
	strncpy(out, hwr_psd_rec.json_val, 33);       /* json_parse_string: strncpy(val, str, len); val[len-1] = '\0'; len = MAX_SSID_LEN */
	out[33 - 1] = '\0';
	return 0;
}

#define L32 "01234567890123456789012345678901"
/* name, vap_index, mesh_sta_index, json_ret, json_val, file, file_len, null_ssid, expected_ret, expected_ssid, exp_json_calls, forked */
hwr_psd_case_t platform_get_ssid_default_suite[] = {
	/* ---- mesh STA: JSON source ---- */
	{ "mesh_sta_json_ok",              3, 3, 0, "MeshBackhaul", "ABCDEFG", 0, 0, 0, "MeshBackhaul", 1, 0 },
	{ "mesh_sta_json_32_chars",        3, 3, 0, L32, "ABCDEFG", 0, 0, 0, L32, 1, 0 },
	{ "mesh_sta_json_fails_serial_ok", 3, 3, -1, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP3-ABCDEFG", 1, 0 },
	{ "mesh_sta_json_ok_no_serial_file", 3, 3, 0, "MeshBackhaul", NULL, 0, 0, 0, "MeshBackhaul", 1, 0 },
	{ "other_vap_json_not_used",       1, 3, 0, "MeshBackhaul", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP1-ABCDEFG", 0, 0 },
	/* ---- serial: last 7 bytes of the file up to the first newline ---- */
	{ "serial_7_bytes_no_newline",     3, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP3-ABCDEFG", 0, 0 },
	{ "serial_8_bytes_with_newline",   3, -2, 0, "", "ABCDEFG\n", 0, 0, 0, "BPI_RDKB-AP3-BCDEFG", 0, 0 },
	{ "serial_10_bytes_no_newline",    3, -2, 0, "", "1234567890", 0, 0, 0, "BPI_RDKB-AP3-4567890", 0, 0 },
	{ "serial_12_bytes_with_newline",  3, -2, 0, "", "SN1234567890\n", 0, 0, 0, "BPI_RDKB-AP3-567890", 0, 0 },
	{ "serial_7_bytes_with_newline_at_end", 3, -2, 0, "", "ABCDEF\n", 0, 0, 0, "BPI_RDKB-AP3-ABCDEF", 0, 0 },
	{ "serial_newline_first_of_last_7", 3, -2, 0, "", "xx\nABCDEF", 0, 0, 0, "BPI_RDKB-AP3-", 0, 0 },
	{ "serial_embedded_nul_cuts_serial", 3, -2, 0, "", "ABxyz\0DEFG", 10, 0, 0, "BPI_RDKB-AP3-yz", 0, 0 },
	{ "serial_with_spaces",            3, -2, 0, "", "AB CD EF", 0, 0, 0, "BPI_RDKB-AP3-B CD EF", 0, 0 },
	{ "serial_crlf_no_cr_in_ssid",     3, -2, 0, "", "ABCDEFG\r\n", 0, 0, 0, "BPI_RDKB-AP3-CDEFG", 0, 0 },
	{ "serial_cr_only_line_end",       3, -2, 0, "", "ABCDEFG\r", 0, 0, 0, "BPI_RDKB-AP3-BCDEFG", 0, 0 },
	/* ---- serial file missing / short / empty ---- */
	{ "serial_file_missing",           3, -2, 0, "", NULL, 0, 0, 0, "BPI_RDKB-AP3-", 0, 0 },
	{ "serial_file_shorter_than_7",    3, -2, 0, "", "ABC", 0, 0, -1, NULL, 0, 0 },
	{ "serial_file_6_bytes",           3, -2, 0, "", "ABCDEF", 0, 0, -1, NULL, 0, 0 },
	{ "serial_file_empty",             3, -2, 0, "", "", 0, 0, -1, NULL, 0, 0 },
	/* ---- vap_index formatting ---- */
	{ "vap_index_0",                   0, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP0-ABCDEFG", 0, 0 },
	{ "vap_index_15",                 15, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP15-ABCDEFG", 0, 0 },
	{ "vap_index_99",                 99, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP99-ABCDEFG", 0, 0 },
	{ "vap_index_minus_1",            -1, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP-1-ABCDEFG", 0, 0 },
	{ "vap_index_int_max",       INT_MAX, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP2147483647-ABCDEFG", 0, 0 },
	{ "vap_index_int_min",       INT_MIN, -2, 0, "", "ABCDEFG", 0, 0, 0, "BPI_RDKB-AP-2147483648-ABCDEFG", 0, 0 },
	/* ---- NULL ssid ---- */
	{ "crash_ssid_null_other_vap",     3, -2, 0, "", "ABCDEFG", 0, 1, -1, NULL, 0, 1 },
	{ "crash_ssid_null_mesh_sta",      3, 3, 0, "MeshBackhaul", "ABCDEFG", 0, 1, -1, NULL, 1, 1 },
	{ "ssid_null_file_missing",        3, -2, 0, "", NULL, 0, 1, -1, NULL, 0, 1 },
	{ NULL, 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0, 0 }
};

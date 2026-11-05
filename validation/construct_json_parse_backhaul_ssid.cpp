/*
 * UNIT TEST (input constructor): construct_json_parse_backhaul_ssid
 *
 * json_parse_backhaul_ssid(out) (platform/banana-pi) reads the string item "Backhaul_SSID" from
 * /nvram/EasymeshCfg.json into out (MAX_SSID_LEN = 33 bytes) through json_parse_string()/json_open_file() and
 * the real cJSON; 0 = read, -1 = not read (the caller then falls back to the nvram default SSID).  The suite is
 * a table of file contents; the runner (json_parse_backhaul_ssid_test.cpp) writes the file to a temporary
 * directory, owns out in a slab whose tail (from byte 33) it POISONS, presets it to 0xA5, calls the function, unpoisons,
 * and checks result and output (value + NUL on success, untouched on failure).  "%V" in file / expected_out is replaced
 * by long_len characters 'k' (long SSIDs are built by the runner).
 * Inputs crossed: BOM (cJSON skips it), normal / 8 / 63 / 64 / 128-char values (fit), escapes (\n, \", A), spaces, UTF-8, key among others /
 * after a nested object / duplicate (first wins), huge file with the key at the end, missing / empty / whitespace-only /
 * truncated / invalid file, array or scalar top-level, other key only, wrong value types (number, null, bool, array,
 * object), BOM, empty value, values of 33 / 34 / 200 / 1000 chars (do not fit), NULL out.
 * Expected = the SAFE contract (no silent truncation, nothing written on failure, no NULL write), so a FAIL is a finding.
 * Rows that crash the unfixed function (NULL out; a malformed file: json_open_file prints cJSON's error pointer with %s from a
 * malloc'd buffer that has no NUL terminator) run forked.
 */
#include "hwr_jbs.h"

char hwr_jbs_path[256];
extern "C" FILE *hwr_jbs_fopen(const char *path, const char *mode)
{
	return fopen(strcmp(path, "/nvram/EasymeshCfg.json") == 0 ? hwr_jbs_path : path, mode);
}

#define K "\"Backhaul_SSID\""
/* name, file, file_len, null_out, expected_ret, expected_out, long_len, forked */
hwr_jbs_case_t json_parse_backhaul_ssid_suite[] = {
	/* ---- read ---- */
	{ "found_simple",              "{" K ": \"MeshBackhaul\"}", 0, 0, 0, "MeshBackhaul", 0, 0 },
	{ "found_10_chars",             "{" K ": \"MyMeshSSID\"}", 0, 0, 0, "MyMeshSSID", 0, 0 },
	{ "found_among_other_items",   "{\"Backhaul_KeyPassphrase\": \"x\", " K ": \"mesh-bh\", \"n\": 5}", 0, 0, 0, "mesh-bh", 0, 0 },
	{ "found_after_nested_object", "{\"a\": {\"b\": [1,2,{\"c\":3}]}, " K ": \"deep\"}", 0, 0, 0, "deep", 0, 0 },
	{ "found_first_of_duplicates", "{" K ": \"one\", " K ": \"two\"}", 0, 0, 0, "one", 0, 0 },
	{ "found_with_spaces",         "{" K ": \"my pass phrase\"}", 0, 0, 0, "my pass phrase", 0, 0 },
	{ "found_escape_quote",        "{" K ": \"a\\\"b\"}", 0, 0, 0, "a\"b", 0, 0 },
	{ "found_escape_newline",      "{" K ": \"a\\nb\"}", 0, 0, 0, "a\nb", 0, 0 },
	{ "found_escape_unicode_A",    "{" K ": \"x\\u0041y\"}", 0, 0, 0, "xAy", 0, 0 },
	{ "found_utf8_bytes",          "{" K ": \"p\xc3\xa4ss\"}", 0, 0, 0, "p\xc3\xa4ss", 0, 0 },
	{ "found_utf8_bom_prefix",     "\xef\xbb\xbf{" K ": \"bom\"}", 0, 0, 0, "bom", 0, 0 },
	{ "found_pretty_printed",      "{\n  \"x\": 1,\n  " K ": \"pretty\"\n}\n", 0, 0, 0, "pretty", 0, 0 },
	{ "found_31_chars",            "{" K ": \"%V\"}", 0, 0, 0, "%V", 31, 0 },
	{ "found_1_char",              "{" K ": \"%V\"}", 0, 0, 0, "%V", 1, 0 },
	{ "found_32_chars_fits",       "{" K ": \"%V\"}", 0, 0, 0, "%V", 32, 0 },
	{ "found_key_after_1mb_pad",   "{\"pad\": \"%V\", " K ": \"late\"}", 0, 0, 0, "late", 1000000, 0 },
	/* ---- not read: -1, output untouched ---- */
	{ "file_missing",              NULL, 0, 0, -1, NULL, 0, 0 },
	{ "crash_file_empty",                "", 0, 0, -1, NULL, 0, 1 },
	{ "crash_file_whitespace_only",      "  \n\t ", 0, 0, -1, NULL, 0, 1 },
	{ "crash_file_truncated_json",       "{" K ": \"abc", 0, 0, -1, NULL, 0, 1 },
	{ "crash_file_not_json",             "hello world", 0, 0, -1, NULL, 0, 1 },
	{ "top_level_array",           "[" K ", \"x\"]", 0, 0, -1, NULL, 0, 0 },
	{ "top_level_string",          "\"Backhaul_SSID\"", 0, 0, -1, NULL, 0, 0 },
	{ "key_missing_other_present", "{\"Backhaul_KeyPassphrase\": \"mesh-pw\"}", 0, 0, -1, NULL, 0, 0 },
	{ "key_only_in_nested_object", "{\"x\": {" K ": \"nested\"}}", 0, 0, -1, NULL, 0, 0 },
	{ "value_number",              "{" K ": 12345678}", 0, 0, -1, NULL, 0, 0 },
	{ "value_null",                "{" K ": null}", 0, 0, -1, NULL, 0, 0 },
	{ "value_true",                "{" K ": true}", 0, 0, -1, NULL, 0, 0 },
	{ "value_array",               "{" K ": [\"a\"]}", 0, 0, -1, NULL, 0, 0 },
	{ "value_object",              "{" K ": {\"a\": \"b\"}}", 0, 0, -1, NULL, 0, 0 },
	/* ---- empty value ---- */
	{ "value_empty_string",        "{" K ": \"\"}", 0, 0, -1, NULL, 0, 0 },
	/* ---- value does not fit in 33 bytes: silently cut ---- */
	{ "value_33_chars_no_fit",    "{" K ": \"%V\"}", 0, 0, -1, NULL, 33, 0 },
	{ "value_34_chars",           "{" K ": \"%V\"}", 0, 0, -1, NULL, 34, 0 },
	{ "value_200_chars",           "{" K ": \"%V\"}", 0, 0, -1, NULL, 200, 0 },
	{ "value_1000_chars",           "{" K ": \"%V\"}", 0, 0, -1, NULL, 1000, 0 },
	/* ---- NULL out ---- */
	{ "out_null_key_missing",      "{\"a\": 1}", 0, 1, -1, NULL, 0, 0 },
	{ "crash_out_null_key_found",  "{" K ": \"secret\"}", 0, 1, -1, NULL, 0, 1 },
	{ NULL, NULL, 0, 0, 0, NULL, 0, 0 }
};

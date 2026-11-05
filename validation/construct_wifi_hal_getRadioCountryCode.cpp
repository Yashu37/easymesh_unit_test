/*
 * UNIT TEST (input constructor): construct_wifi_hal_getRadioCountryCode
 *
 * wifi_hal_getRadioCountryCode(radioIndex, output_string) looks the radio up by rdk index and writes the
 * radio's country as the two letter code with get_coutry_str_from_code() (table lookup over wifi_country_map,
 * "US" for a code that is not in the table); an unknown radio returns -1 (ipc_server_output allocates
 * HAL_IPC_MAX_STRING_LEN = 64 bytes for the output).
 *
 * The suite is a table of "worlds" (radios with rdk index and country code) plus the query and the expected
 * output; the runner (wifi_hal_getRadioCountryCode_test.cpp) builds the world in runner-owned slabs (REAL
 * wifi_radio_operationParam_t), POISONS the tails (including the bytes behind the 64-byte output buffer), calls
 * the function, unpoisons and checks.
 * Inputs crossed: common countries (US, GB, DE, FR, JP, CN, IN, AU, BR, AC, ZW), the codes of
 * wifi_countrycode_type_t that are NOT in the table (AX, BL, CW, MF, SX, BQ, 00: reported as "US") and the one
 * whose table string is lower case (JO: "jo"), ONE row that checks every value of the enum against its own two
 * letter name, codes outside the enum (wifi_countrycode_max, -1, INT_MAX: the documented default "US"),
 * radioIndex 0 / 1 / 2 / non-sequential rdk indexes, unknown / negative / INT_MIN / INT_MAX indexes, duplicate rdk
 * index (first wins), no radios, output untouched on a failed lookup, repeated calls, the log, and a NULL
 * output_string (forked).  Expected result is the SAFE contract (the country that was configured is the country
 * reported), so a FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gct.h"

hwr_gct_code_t hwr_gct_all[] = {
#include "hwr_gct_codes.inc"
};
int hwr_gct_all_n = (int)(sizeof(hwr_gct_all) / sizeof(hwr_gct_all[0]));

#define ONE(c)   1, { { 0, (c) }, { 0, 0 }, { 0, 0 } }
#define NOR      0, { { 0, 0 }, { 0, 0 }, { 0, 0 } }
#define UT NULL
#define CC(n, code, str)  { n, ONE(code), 0, 0, 1, 0, 0, str, 0, 0 }
/* name, nradios, radios[3], query, null_out, calls, check_log, expected_ret, expected_out, forked, all_codes */
hwr_gct_case_t wifi_hal_getRadioCountryCode_suite[] = {
	/* ---- common countries ---- */
	CC("country_US", wifi_countrycode_US, "US"),
	CC("country_GB", wifi_countrycode_GB, "GB"),
	CC("country_DE", wifi_countrycode_DE, "DE"),
	CC("country_FR", wifi_countrycode_FR, "FR"),
	CC("country_JP", wifi_countrycode_JP, "JP"),
	CC("country_CN", wifi_countrycode_CN, "CN"),
	CC("country_IN", wifi_countrycode_IN, "IN"),
	CC("country_AU", wifi_countrycode_AU, "AU"),
	CC("country_BR", wifi_countrycode_BR, "BR"),
	CC("country_AC_first_in_table", wifi_countrycode_AC, "AC"),
	CC("country_ZW", wifi_countrycode_ZW, "ZW"),
	/* ---- the table string is lower case ---- */
	CC("country_JO_table_string_is_lower_case", wifi_countrycode_JO, "JO"),
	/* ---- valid codes that are not in the table: reported as the default "US" ---- */
	CC("country_AX_missing_from_table", wifi_countrycode_AX, "AX"),
	CC("country_BL_missing_from_table", wifi_countrycode_BL, "BL"),
	CC("country_CW_missing_from_table", wifi_countrycode_CW, "CW"),
	CC("country_MF_missing_from_table", wifi_countrycode_MF, "MF"),
	CC("country_SX_missing_from_table", wifi_countrycode_SX, "SX"),
	CC("country_BQ_missing_from_table", wifi_countrycode_BQ, "BQ"),
	CC("country_00_world_domain_missing_from_table", wifi_countrycode_00, "00"),
	{ "every_enum_code_reports_its_own_name", NOR, 0, 0, 1, 0, 0, "", 0, 1 },
	/* ---- codes outside the enum: documented default "US" (design note, not counted) ---- */
	CC("code_wifi_countrycode_max_default_US", wifi_countrycode_max, "US"),
	CC("code_minus_1_default_US", -1, "US"),
	CC("code_int_max_default_US", INT_MAX, "US"),
	/* ---- lookup by rdk index ---- */
	{ "three_radios_query_0",  3, { { 0, wifi_countrycode_US }, { 1, wifi_countrycode_DE }, { 2, wifi_countrycode_JP } }, 0, 0, 1, 0, 0, "US", 0, 0 },
	{ "three_radios_query_1",  3, { { 0, wifi_countrycode_US }, { 1, wifi_countrycode_DE }, { 2, wifi_countrycode_JP } }, 1, 0, 1, 0, 0, "DE", 0, 0 },
	{ "three_radios_query_2",  3, { { 0, wifi_countrycode_US }, { 1, wifi_countrycode_DE }, { 2, wifi_countrycode_JP } }, 2, 0, 1, 0, 0, "JP", 0, 0 },
	{ "swapped_rdk_indexes_query_0", 2, { { 1, wifi_countrycode_DE }, { 0, wifi_countrycode_GB }, { 0, 0 } }, 0, 0, 1, 0, 0, "GB", 0, 0 },
	{ "rdk_index_gap_query_5", 2, { { 0, wifi_countrycode_US }, { 5, wifi_countrycode_FR }, { 0, 0 } }, 5, 0, 1, 0, 0, "FR", 0, 0 },
	{ "duplicate_rdk_index_first_wins", 2, { { 3, wifi_countrycode_IN }, { 3, wifi_countrycode_CN }, { 0, 0 } }, 3, 0, 1, 0, 0, "IN", 0, 0 },
	/* ---- lookup failures: -1, output untouched ---- */
	{ "unknown_radio_not_present", 2, { { 0, wifi_countrycode_US }, { 1, wifi_countrycode_DE }, { 0, 0 } }, 2, 0, 1, 0, -1, UT, 0, 0 },
	{ "no_radios",             NOR, 0, 0, 1, 0, -1, UT, 0, 0 },
	{ "radio_index_minus_1",   ONE(wifi_countrycode_US), -1, 0, 1, 0, -1, UT, 0, 0 },
	{ "radio_index_int_min",   ONE(wifi_countrycode_US), INT_MIN, 0, 1, 0, -1, UT, 0, 0 },
	{ "radio_index_int_max",   ONE(wifi_countrycode_US), INT_MAX, 0, 1, 0, -1, UT, 0, 0 },
	{ "unknown_radio_logs_error", ONE(wifi_countrycode_US), 4, 0, 1, 1, -1, UT, 0, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_result", 2, { { 0, wifi_countrycode_US }, { 1, wifi_countrycode_NL }, { 0, 0 } }, 1, 0, 3, 0, 0, "NL", 0, 0 },
	{ "log_ok_has_no_error_line", ONE(wifi_countrycode_US), 0, 0, 1, 2, 0, "US", 0, 0 },
	/* ---- crash group (forked): NULL output_string, radio found ---- */
	{ "crash_output_null_radio_0", ONE(wifi_countrycode_US), 0, 1, 1, 0, -1, UT, 1, 0 },
	{ "crash_output_null_radio_1", 2, { { 0, wifi_countrycode_US }, { 1, wifi_countrycode_DE }, { 0, 0 } }, 1, 1, 1, 0, -1, UT, 1, 0 },
	{ "crash_output_null_unmapped_code", ONE(wifi_countrycode_AX), 0, 1, 1, 0, -1, UT, 1, 0 },
	{ "output_null_unknown_radio", ONE(wifi_countrycode_US), 7, 1, 1, 0, -1, UT, 0, 0 },
	{ NULL, NOR, 0, 0, 0, 0, 0, NULL, 0, 0 }
};

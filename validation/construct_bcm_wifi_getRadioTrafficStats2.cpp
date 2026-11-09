/*
 * UNIT TEST (input constructor): construct_bcm_wifi_getRadioTrafficStats2
 *
 * wifi_getRadioTrafficStats2(radioIndex, &stats) (platform/broadcom) looks up the radio and its primary interface, sends the vendor GET_RADIO_INFO
 * command and lets the real get_radio_diag_handler copy the 21 statistics (12 packet / byte counters, noise floor, channel utilization, activity
 * factor, carrier-sense / retransmission metrics, 3 noise-floor values, statistics start time) into the caller's structure.  The kernel stub builds real
 * libnl vendor messages.  The suite crosses: value seeds 0 / 1 / 7 / 1000 / 0xFFFFFFFF / 2^40 / 2^62 / 2^64-64 (the 64-bit counters and the signed
 * values), a second call, unknown / negative / INT_MAX radio index, no radio, radio without interface, command message NULL, a failing send (the handler
 * has already run), and a reply with the vendor data, the radio-info nest or one statistic missing (first, last, signed, middle ones).
 * ASSUMPTION for the missing-data rows: a reply that cannot be parsed is an error - the function must return WIFI_HAL_ERROR (RETURN_ERR) and leave the
 * caller's structure alone.  The original returns RETURN_OK without having written anything, so the caller reads uninitialized statistics.
 * The row named invalid_* runs last: a NULL output structure is written through by the handler (expected: WIFI_HAL_ERROR, nothing written).
 * Row layout: see bgt_case_t in hwr_bgt.h.
 */
#include <limits.h>
#include "hwr_bgt.h"

#define OK   RETURN_OK
#define ERR  RETURN_ERR
/* default row: radio 0 exists with an interface, output buffer, no failures, 'attr' left out of the reply */
#define R(name, base, omit_reply, omit_attr, ret, untouched) \
	{ name, 0, 1, 1, 1, base, 0, 0, omit_reply, omit_attr, ret, untouched, 1, 0 }

bgt_case_t bcm_wifi_getRadioTrafficStats2_suite[] = {
	/* ---- statistics ---- */
	R("seed_0",                          0ULL, 0, 0, OK, 0),
	R("seed_1",                          1ULL, 0, 0, OK, 0),
	R("seed_7_signed_values",            7ULL, 0, 0, OK, 0),
	R("seed_1000",                    1000ULL, 0, 0, OK, 0),
	R("seed_0xFFFFFFFF",        0xFFFFFFFFULL, 0, 0, OK, 0),
	R("seed_2_pow_40",       0x10000000000ULL, 0, 0, OK, 0),
	R("seed_2_pow_62",     0x4000000000000000ULL, 0, 0, OK, 0),
	R("seed_near_u64_max", 0xFFFFFFFFFFFFFFC0ULL, 0, 0, OK, 0),
	{ "two_calls_same_result",          0, 1, 1, 1, 4242ULL, 0, 0, 0, 0, OK, 0, 2, 0 },
	/* ---- lookups and command failures ---- */
	{ "radio_index_unknown",            7, 1, 1, 1, 5ULL, 0, 0, 0, 0, ERR, 1, 1, 0 },
	{ "radio_index_negative",          -1, 1, 1, 1, 5ULL, 0, 0, 0, 0, ERR, 1, 1, 0 },
	{ "radio_index_int_max",      INT_MAX, 1, 1, 1, 5ULL, 0, 0, 0, 0, ERR, 1, 1, 0 },
	{ "no_radio_at_all",                0, 0, 1, 1, 5ULL, 0, 0, 0, 0, ERR, 1, 1, 0 },
	{ "radio_without_interface",        0, 1, 0, 1, 5ULL, 0, 0, 0, 0, ERR, 1, 1, 0 },
	{ "command_message_null",           0, 1, 1, 1, 5ULL, 1, 0, 0, 0, ERR, 1, 1, 0 },
	{ "send_fails_after_handler",       0, 1, 1, 1, 5ULL, 0, -1, 0, 0, ERR, 0, 1, 0 },
	/* ---- unparsable replies: must be an error and leave the output alone (original: success, nothing written) ---- */
	R("vendor_data_missing",             5ULL, 1, 0, ERR, 1),
	R("radio_info_nest_missing",         5ULL, 2, 0, ERR, 1),
	R("missing_bytes_sent",              5ULL, 0, 1, ERR, 1),
	R("missing_packets_received",        5ULL, 0, 4, ERR, 1),
	R("missing_packets_other_received",  5ULL, 0, 12, ERR, 1),
	R("missing_noise_floor_signed",      5ULL, 0, 13, ERR, 1),
	R("missing_channel_utilization",     5ULL, 0, 14, ERR, 1),
	R("missing_activity_factor",         5ULL, 0, 15, ERR, 1),
	R("missing_median_noise_floor",      5ULL, 0, 20, ERR, 1),
	R("missing_statistics_start_time",   5ULL, 0, 21, ERR, 1),
	/* ---- invalid input that crashes the original (run last) ---- */
	{ "invalid_output_struct_null",     0, 1, 1, 0, 5ULL, 0, 0, 0, 0, ERR, 1, 1, 1 },
	{ NULL }
};

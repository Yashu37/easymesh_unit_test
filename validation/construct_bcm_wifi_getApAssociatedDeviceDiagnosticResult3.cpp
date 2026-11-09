/*
 * UNIT TEST (input constructor): construct_bcm_wifi_getApAssociatedDeviceDiagnosticResult3
 *
 * wifi_getApAssociatedDeviceDiagnosticResult3(apIndex, &array, &size) (platform/broadcom) asks the Broadcom driver over a vendor nl80211 command for the
 * station list (RDK_VENDOR_ATTR_STA_NUM + a nested list of MAC entries, get_sta_list_handler), calloc's one wifi_associated_dev3_t per station and
 * queries every station with the vendor GET_STATION command (get_sta_stats_handler: ~35 statistics attributes, standard / bandwidth strings, MLD
 * fields, then the derived DataFramesSentAck / NoAck / PacketsSent).  The handlers are the real ones, fed with real libnl messages by the stub kernel
 * of the handler file.  The suite crosses: 0..8 stations, every operating standard (A B G N AC AD AX BE, 0 and 99 = unknown) and channel width
 * (20 40 80 160 320, 0 and 99), both branches of the packet / byte ratio, MLD enabled / disabled, apIndex 0 / 15 / INT_MAX, interface found /
 * missing / other vap, vendor command message NULL (list / stats), a failing list / stats command (also for the middle station), malformed lists
 * (STA_NUM 0, more / fewer entries than STA_NUM, 4-byte MAC entries, out-of-memory STA_NUM), a second call.  Rows named invalid_* run last: NULL output
 * pointers, unchecked calloc, and a vendor MAC / MLD-MAC attribute longer than 6 bytes that is copied with nla_len() bytes into a 6-byte field
 * (overflows into the next fields; with 4000 bytes it leaves the heap block).  The expected result there is the safe one: WIFI_HAL_ERROR with the outputs
 * untouched for NULL pointers, WIFI_HAL_ERROR with *array NULL / *size 0 and nothing allocated for a calloc failure, and the attribute rejected (or
 * truncated to 6 bytes) without touching the neighbouring fields.
 * Row layout: see bga_case_t in hwr_bga.h.
 */
#include <limits.h>
#include "hwr_bga.h"

#define OK   WIFI_HAL_SUCCESS
#define ERR  WIFI_HAL_ERROR
/* default row: ap 0, interface found, both outputs valid, no failures */
#define R(name, nsta, txb, txp, fl, std, bw, mld, mldl) \
	{ name, 0, 1, 0, nsta, txb, txp, fl, std, bw, mld, mldl, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 0 }

bga_case_t bcm_wifi_getApAssociatedDeviceDiagnosticResult3_suite[] = {
	/* ---- stations ---- */
	R("no_stations",                    0, 14700, 20, 1, 7, 3, -1, 0),
	R("one_station",                    1, 14700, 20, 1, 7, 3, -1, 0),
	R("two_stations",                   2, 14700, 20, 1, 7, 3, -1, 0),
	R("three_stations",                 3, 14700, 20, 1, 7, 3, -1, 0),
	R("eight_stations",                 8, 14700, 20, 1, 7, 3, -1, 0),
	/* ---- operating standard ---- */
	R("standard_a",                     1, 14700, 20, 1, 1, 3, -1, 0),
	R("standard_b",                     1, 14700, 20, 1, 2, 3, -1, 0),
	R("standard_g",                     1, 14700, 20, 1, 3, 3, -1, 0),
	R("standard_n",                     1, 14700, 20, 1, 4, 3, -1, 0),
	R("standard_ac",                    1, 14700, 20, 1, 5, 3, -1, 0),
	R("standard_ad",                    1, 14700, 20, 1, 6, 3, -1, 0),
	R("standard_ax",                    1, 14700, 20, 1, 7, 3, -1, 0),
	R("standard_be",                    1, 14700, 20, 1, 8, 3, -1, 0),
	R("standard_0_unknown",             1, 14700, 20, 1, 0, 3, -1, 0),
	R("standard_99_unknown",            1, 14700, 20, 1, 99, 3, -1, 0),
	/* ---- channel width ---- */
	R("width_20",                       1, 14700, 20, 1, 7, 1, -1, 0),
	R("width_40",                       1, 14700, 20, 1, 7, 2, -1, 0),
	R("width_80",                       1, 14700, 20, 1, 7, 3, -1, 0),
	R("width_160",                      1, 14700, 20, 1, 7, 4, -1, 0),
	R("width_320",                      1, 14700, 20, 1, 7, 5, -1, 0),
	R("width_0_unknown",                1, 14700, 20, 1, 7, 0, -1, 0),
	R("width_99_unknown",               1, 14700, 20, 1, 7, 99, -1, 0),
	/* ---- derived packet counters ---- */
	R("bytes_ratio_below_packets",      2, 2940, 100, 3, 7, 3, -1, 0),
	R("bytes_ratio_above_packets",      2, 1470000, 10, 3, 7, 3, -1, 0),
	R("no_failed_retries",              2, 14700, 20, 0, 7, 3, -1, 0),
	/* ---- MLD ---- */
	R("mld_enabled_6_byte_mac",         2, 14700, 20, 1, 7, 3, 1, 6),
	R("mld_disabled_attribute_0",       1, 14700, 20, 1, 7, 3, 0, 0),
	/* ---- apIndex / interface ---- */
	{ "ap_index_15",                   15, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 0 },
	{ "ap_index_int_max",         INT_MAX, 1, 0, 1, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 0 },
	{ "iface_missing",                  0, 0, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, ERR, 0, 1,0, 0 },
	{ "iface_other_vap_index",          0, 2, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, ERR, 0, 1,0, 0 },
	{ "two_calls_fresh_arrays",         0, 1, 0, 3, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 2, OK, -1, 0,0, 0 },
	/* ---- vendor command failures ---- */
	{ "list_command_message_null",      0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 1,0,0,-1,0,0, 1, ERR, 0, 1,0, 0 },
	{ "list_command_fails",             0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,-1,-1,0,0, 1, ERR, 0, 1,0, 0 },
	{ "stats_command_message_null",     0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,1,0,-1,0,0, 1, ERR, 0, 0,1, 0 },
	{ "stats_fails_first_station",      0, 1, 0, 3, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,0,0,0, 1, ERR, 0, 0,1, 0 },
	{ "stats_fails_middle_station",     0, 1, 0, 3, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,1,0,0, 1, ERR, 0, 0,1, 0 },
	/* ---- malformed station list: the function reports no stations ---- */
	{ "sta_num_0_with_entries",         0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, 0, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, 0, 0,0, 0 },
	{ "sta_num_larger_than_entries",    0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, 3, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, 0, 0,0, 0 },
	{ "sta_num_smaller_than_entries",   0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, 1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, 0, 0,0, 0 },
	{ "list_entry_4_bytes",             0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 4, 0, 0,0,0,-1,0,0, 1, OK, 0, 0,0, 0 },
	{ "sta_num_huge_allocation_fails",  0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, 4000000000LL, 0, 6, 0, 0,0,0,-1,0,1000000, 1, OK, 0, 0,0, 0 },
	/* ---- invalid inputs and failures that crash / corrupt the original (run last) ---- */
	{ "invalid_array_ptr_null",         0, 1, 1, 1, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_size_ptr_null",          0, 1, 2, 1, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_both_ptrs_null",         0, 1, 3, 1, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, ERR, 0, 1,0, 1 },
	{ "invalid_calloc_fails_2_stations",0, 1, 0, 2, 14700, 20, 1, 7, 3, -1, 0, 6, -1, -1, 6, 0, 0,0,0,-1,1,0, 1, ERR, 0, 0,1, 1 },
	{ "invalid_mac_attr_8_bytes",       0, 1, 0, 1, 14700, 20, 1, 7, 3, -1, 0, 8, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 1 },
	{ "invalid_mld_mac_attr_24_bytes",  0, 1, 0, 1, 14700, 20, 1, 7, 3,  1, 24, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 1 },
	{ "invalid_mac_attr_4000_bytes",    0, 1, 0, 1, 14700, 20, 1, 7, 3, -1, 0, 4000, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 1 },
	{ "invalid_mld_mac_attr_4000_bytes",0, 1, 0, 1, 14700, 20, 1, 7, 3,  1, 4000, 6, -1, -1, 6, 0, 0,0,0,-1,0,0, 1, OK, -1, 0,0, 1 },
	{ NULL }
};

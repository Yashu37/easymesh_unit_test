/*
 * UNIT TEST (input constructor): construct_wifi_hal_getMultiPskClientKey
 *
 * wifi_hal_getMultiPskClientKey(apIndex, mac, key) is the HAL IPC server wrapper for the getter
 * wifi_getMultiPskClientKey (halinterface: "@param[out] key: structure to store the key of the client").  In
 * rdk-wifi-hal it is an EMPTY function: it logs two debug lines, stores nothing in *key and returns 0.
 *
 * A getter must not report success without writing its output, so the SAFE contract checked here is:
 *   - the call returns an error (RETURN_ERR = "not implemented") for every input,
 *   - *key is not modified and nothing behind it is touched (the runner presets it to 0xA5 and poisons the tail),
 *   - the client MAC is not modified, a NULL mac / NULL key is tolerated.
 * Inputs crossed: apIndex INT_MIN, -1, 0, 1, 15, 16, 255, INT_MAX with a normal MAC; at AP 0 an all-zero,
 * broadcast, multicast and locally administered MAC; a NULL mac, a NULL key and both NULL; repeated calls; the
 * log text.  A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gmk.h"

#define NM  { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }
/* name, ap_index, mac, null_mask, calls, check_log */
hwr_gmk_case_t wifi_hal_getMultiPskClientKey_suite[] = {
	{ "ap_int_min",              INT_MIN, NM, 0, 1, 0 },
	{ "ap_m1",                   -1,      NM, 0, 1, 0 },
	{ "ap_0",                    0,       NM, 0, 1, 0 },
	{ "ap_1",                    1,       NM, 0, 1, 0 },
	{ "ap_15",                   15,      NM, 0, 1, 0 },
	{ "ap_16",                   16,      NM, 0, 1, 0 },
	{ "ap_255",                  255,     NM, 0, 1, 0 },
	{ "ap_int_max",              INT_MAX, NM, 0, 1, 0 },
	{ "mac_all_zero",            0, { 0, 0, 0, 0, 0, 0 }, 0, 1, 0 },
	{ "mac_broadcast",           0, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 0, 1, 0 },
	{ "mac_multicast",           0, { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 }, 0, 1, 0 },
	{ "mac_locally_administered", 0, { 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f }, 0, 1, 0 },
	{ "mac_null",                0, NM, 1, 1, 0 },
	{ "key_null",                0, NM, 2, 1, 0 },
	{ "key_null_ap_1",           1, NM, 2, 1, 0 },
	{ "mac_and_key_null",        0, NM, 3, 1, 0 },
	{ "repeated_calls_x3",       2, NM, 0, 3, 0 },
	{ "log_has_function_name_and_enter", 1, NM, 0, 1, 1 },
	{ NULL, 0, { 0 }, 0, 0, 0 }
};

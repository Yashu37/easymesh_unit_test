/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_getHalCapability
 *
 * wifi_hal_getHalCapability(hal) (generic branch).  Inputs crossed: hal NULL / exact-size heap object; num_radios 0 .. MAX_NUM_RADIOS .. beyond; interfaces per radio 0-3;
 * the four shell replies (serial, model, image, CM mac) empty / short / without newline / 63 / 64 / 100 / 254 characters (fields are 64 bytes); easymesh-off flag present,
 * absent and access() failing; EM_CFG_FILE reads (al mac ok / failed / malformed, colocated mode ok / failed / 0 / 2); the interface found or not and its name (eth / lo /
 * lan / brlan are left alone, others are configured: success or failure); eth0 mac read failing; radios whose RDK index is not their position.  The expected result is
 * derived by the runner from these inputs (correct, bounded behaviour).  Rows with last = 1 break the original (overlong replies spill out of the 64-byte fields, too many
 * radios index past the arrays, a missing radio is dereferenced): they run LAST.
 */
#include "hwr_ghc.h"

#define OK 0
#define X8   "XXXXXXXX"
#define X16  X8 X8
#define X32  X16 X16
#define X63  X32 X16 X8 "XXXXXXX"
#define X64  X32 X32
#define X100 X64 X32 "XXXX"
#define X200 X100 X100
#define X254 X200 X32 X16 "XXXXXX"
#define X255 X200 X32 X16 "XXXXXXX"
#define TXT  "SN1\n", "MODEL1\n", "IMG1\n", "aa:bb:cc:dd:ee:01\n"
#define EM   0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 0, 0
#define M    MAX_NUM_RADIOS
/* name, hal_mode, nrad, shift, ifaces, serial, model, image, cm, off_flag, access_errno, js_ret, js_val, ji_ret, ji_val, found, ifname, conf_ret, eth_ret, expected_ret, last */
hwr_ghc_case_t sg_wifi_hal_getHalCapability_suite[] = {
	{ "two_radios_two_ifaces",        1, 2, 0, 2, TXT, EM, OK, 0 },
	{ "one_radio_one_iface",          1, 1, 0, 1, TXT, EM, OK, 0 },
	{ "zero_radios",                  1, 0, 0, 0, TXT, EM, OK, 0 },
	{ "max_radios",                   1, M, 0, 3, TXT, EM, OK, 0 },
	{ "radios_without_interfaces",    1, 2, 0, 0, TXT, EM, OK, 0 },
	{ "radios_three_interfaces",      1, 2, 0, 3, TXT, EM, OK, 0 },
	{ "replies_empty",                1, 2, 0, 1, NULL, NULL, NULL, NULL, EM, OK, 0 },
	{ "replies_without_newline",      1, 2, 0, 1, "SN", "MODEL", "IMG", "aa:bb:cc:dd:ee:02", EM, OK, 0 },
	{ "replies_only_newline",         1, 2, 0, 1, "\n", "\n", "\n", "\n", EM, OK, 0 },
	{ "serial_63_chars",              1, 2, 0, 1, X63, "MODEL1\n", "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 0 },
	{ "serial_63_chars_newline",      1, 2, 0, 1, X63 "\n", "MODEL1\n", "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 0 },
	{ "model_63_chars",               1, 2, 0, 1, "SN1\n", X63, "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 0 },
	{ "image_63_chars",               1, 2, 0, 1, "SN1\n", "MODEL1\n", X63, "aa:bb:cc:dd:ee:01\n", EM, OK, 0 },
	{ "cm_mac_malformed",             1, 2, 0, 1, "SN1\n", "MODEL1\n", "IMG1\n", "garbage\n", EM, OK, 0 },
	{ "easymesh_off_flag_present",    1, 2, 0, 1, TXT, 1, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 0, 0, OK, 0 },
	{ "easymesh_off_eth0_fails",      1, 2, 0, 1, TXT, 1, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 0, -1, OK, 0 },
	{ "access_fails_eacces",          1, 2, 0, 1, TXT, 0, 13, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 0, 0, OK, 0 },
	{ "json_al_mac_read_fails",       1, 2, 0, 1, TXT, 0, 0, -1, NULL, 0, 1, 1, "wl0", 0, 0, OK, 0 },
	{ "json_al_mac_malformed",        1, 2, 0, 1, TXT, 0, 0, 0, "zz", 0, 1, 1, "wl0", 0, 0, OK, 0 },
	{ "json_colocated_read_fails",    1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", -1, 0, 1, "wl0", 0, 0, OK, 0 },
	{ "json_colocated_mode_2",        1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 2, 1, "wl0", 0, 0, OK, 0 },
	{ "json_colocated_mode_0",        1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 0, 1, "wl0", 0, 0, OK, 0 },
	{ "json_both_fail",               1, 2, 0, 1, TXT, 0, 0, -1, NULL, -1, 0, 1, "wl0", 0, 0, OK, 0 },
	{ "interface_not_found",          1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 0, NULL, 0, 0, OK, 0 },
	{ "ifname_eth0_conf_fails_ignored", 1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "eth0", 1, 0, OK, 0 },
	{ "ifname_lo_conf_fails_ignored", 1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "lo", 1, 0, OK, 0 },
	{ "ifname_brlan0_conf_fails_ignored", 1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "brlan0", 1, 0, OK, 0 },
	{ "ifname_wl0_conf_ok",           1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 0, 0, OK, 0 },
	{ "ifname_wl0_conf_fails",        1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 1, 0, OK, 0 },
	{ "eth0_mac_fails",               1, 2, 0, 1, TXT, 0, 0, 0, "11:22:33:44:55:66", 0, 1, 1, "wl0", 0, -1, OK, 0 },
	{ "hal_null",                     0, 2, 0, 1, TXT, EM, WIFI_HAL_INVALID_ARGUMENTS, 0 },
	/* overlong replies / bad radio tables: break the original, run last */
	{ "serial_64_chars",              1, 2, 0, 1, X64, "MODEL1\n", "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 1 },
	{ "serial_100_chars",             1, 2, 0, 1, X100, "MODEL1\n", "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 1 },
	{ "model_100_chars",              1, 2, 0, 1, "SN1\n", X100, "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 1 },
	{ "image_100_chars",              1, 2, 0, 1, "SN1\n", "MODEL1\n", X100, "aa:bb:cc:dd:ee:01\n", EM, OK, 1 },
	{ "num_radios_max_plus_1",        1, M + 1, 0, 1, TXT, EM, OK, 1 },
	{ "radio_rdk_index_shifted",      1, 2, 1, 1, TXT, EM, OK, 1 },
	{ "image_255_chars",              1, 2, 0, 1, "SN1\n", "MODEL1\n", X255, "aa:bb:cc:dd:ee:01\n", EM, OK, 1 },
	{ "serial_254_chars",             1, 2, 0, 1, X254, "MODEL1\n", "IMG1\n", "aa:bb:cc:dd:ee:01\n", EM, OK, 1 },
	{ "num_radios_8",                 1, 8, 0, 1, TXT, EM, OK, 1 },
	{ NULL }
};

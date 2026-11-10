/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_setRadioTransmitPower
 *
 * wifi_hal_setRadioTransmitPower(radioIndex, txpower).  Inputs crossed: radioIndex 0 / 1 / 3 / out of range (4, 99, UINT_MAX) / no radio; g_wifi_hal.platform_flags without / with
 * PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY (0x8), alone and among other bits (0x7, 0xFFFFFFF7, 0xFFFFFFFF); the interface finders returning an interface / NULL (primary only, private only, both, neither);
 * txpower 0 / 1 / 20 / 100 / UINT_MAX (forwarded unchanged); wifi_drv_set_txpower returning 0 / -1 / 5.  Expected (CORRECT behaviour): no radio -> -1 and no finder / driver call; the flag decides the
 * finder (primary when bit 3 is set, private otherwise), the finder gets the radio; no interface -> -1 and no driver call; otherwise one driver call with that interface and the same txpower, result 0 for a
 * 0 return and -1 for any other.  No crash case is expected.
 */
#include "hwr_wtp.h"
#include <limits.h>

/* name, radioIndex, no_radio, flags, has_primary, has_private, txpower, drv_ret, last */
hwr_wtp_case_t sg_wifi_hal_setRadioTransmitPower_suite[] = {
	/* ---- radio lookup ---- */
	{ "no_radio",                  0, 1, 0x0, 1,1, 20, 0, 0 },
	{ "radio_index_4",             4, 0, 0x0, 1,1, 20, 0, 0 },
	{ "radio_index_99",           99, 0, 0x8, 1,1, 20, 0, 0 },
	{ "radio_index_uint_max", UINT_MAX, 0, 0x0, 1,1, 20, 0, 0 },
	{ "radio_index_1",             1, 0, 0x0, 1,1, 20, 0, 0 },
	{ "radio_index_3",             3, 0, 0x8, 1,1, 20, 0, 0 },
	/* ---- finder selection by platform_flags ---- */
	{ "flags_0_private_used",      0, 0, 0x0, 1,1, 20, 0, 0 },
	{ "flag_primary_primary_used", 0, 0, 0x8, 1,1, 20, 0, 0 },
	{ "flags_0x7_private_used",    0, 0, 0x7, 1,1, 20, 0, 0 },
	{ "flags_all_but_primary_private_used", 0, 0, 0xFFFFFFF7u, 1,1, 20, 0, 0 },
	{ "flags_all_set_primary_used",0, 0, 0xFFFFFFFFu, 1,1, 20, 0, 0 },
	{ "flag_primary_with_other_bits", 1, 0, 0xF, 1,1, 20, 0, 0 },
	/* ---- no interface ---- */
	{ "private_missing",           0, 0, 0x0, 1,0, 20, 0, 0 },
	{ "primary_missing",           0, 0, 0x8, 0,1, 20, 0, 0 },
	{ "both_missing_private_mode", 0, 0, 0x0, 0,0, 20, 0, 0 },
	{ "both_missing_primary_mode", 0, 0, 0x8, 0,0, 20, 0, 0 },
	{ "only_primary_exists_private_mode", 1, 0, 0x0, 1,0, 20, 0, 0 },
	/* ---- txpower forwarded unchanged ---- */
	{ "txpower_0",                 0, 0, 0x0, 1,1, 0, 0, 0 },
	{ "txpower_1",                 0, 0, 0x8, 1,1, 1, 0, 0 },
	{ "txpower_100",               0, 0, 0x0, 1,1, 100, 0, 0 },
	{ "txpower_uint_max",          0, 0, 0x0, 1,1, UINT_MAX, 0, 0 },
	/* ---- driver result ---- */
	{ "driver_fails_minus1",       0, 0, 0x0, 1,1, 20,-1, 0 },
	{ "driver_fails_5",            0, 0, 0x8, 1,1, 20, 5, 0 },
	{ "driver_fails_int_min",      1, 0, 0x0, 1,1, 20, INT_MIN, 0 },
	{ NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};

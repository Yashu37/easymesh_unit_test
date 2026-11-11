/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_RMBeaconRequestCallbackRegister
 *
 * wifi_hal_RMBeaconRequestCallbackRegister(apIndex, beaconReportCallback).  Inputs crossed: apIndex 0 / 1 / 7 / 14 (valid, last valid) and 15 / 16 / 100 / UINT_MAX / 0x80000000 (out of range); the callback
 * already registered at apIndex none / A / B; the callback passed NULL / A / B; the callbacks table available / not available.  The other slots hold callback C.  Expected (CORRECT behaviour): apIndex >= 15 ->
 * RETURN_ERR without reading or writing any slot; no table -> RETURN_ERR; a slot that already holds a callback is NOT replaced (RETURN_ERR, slot unchanged); an empty slot receives the callback (NULL included)
 * and RETURN_OK; no other slot, neighbouring member or the guard slab is touched.  No crash case is expected.
 */
#include "hwr_wrr.h"
#include <limits.h>

/* name, ap_index, registered, passed, no_table, last */
hwr_wrr_case_t sg_wifi_hal_RMBeaconRequestCallbackRegister_suite[] = {
	{ "idx0_register_a",            0, 0, 1, 0, 0 },
	{ "idx1_register_b",            1, 0, 2, 0, 0 },
	{ "idx7_register_a",            7, 0, 1, 0, 0 },
	{ "idx14_last_valid",           14, 0, 2, 0, 0 },
	{ "idx3_register_null_on_empty",3, 0, 0, 0, 0 },
	{ "idx3_already_registered_other", 3, 1, 2, 0, 0 },
	{ "idx3_already_registered_same",  3, 2, 2, 0, 0 },
	{ "idx14_already_registered_null", 14, 1, 0, 0, 0 },
	{ "idx15_first_invalid_a",      15, 0, 1, 0, 0 },
	{ "idx15_first_invalid_null",   15, 0, 0, 0, 0 },
	{ "idx16",                      16, 0, 1, 0, 0 },
	{ "idx100",                     100, 0, 2, 0, 0 },
	{ "idx_uint_max",               UINT_MAX, 0, 1, 0, 0 },
	{ "idx_0x80000000",             0x80000000u, 0, 1, 0, 0 },
	{ "idx15_invalid_and_no_table", 15, 0, 1, 1, 0 },
	{ "table_not_available_idx0",   0, 0, 1, 1, 0 },
	{ "table_not_available_idx14",  14, 1, 2, 1, 0 },
	{ "table_not_available_null",   5, 0, 0, 1, 0 },
	{ NULL }
};

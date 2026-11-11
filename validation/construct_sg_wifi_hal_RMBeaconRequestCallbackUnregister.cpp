/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_RMBeaconRequestCallbackUnregister
 *
 * wifi_hal_RMBeaconRequestCallbackUnregister(apIndex, beaconReportCallback).  Inputs crossed: apIndex 0 / 1 / 7 / 14 (valid, last valid) and 15 / 16 / 100 / UINT_MAX (out of range); the callback registered at
 * apIndex none / A / B; the callback passed NULL / A / B; the callbacks table available / not available.  The other slots of the table hold callback C.  Expected (CORRECT behaviour): apIndex >= 15 ->
 * RETURN_ERR without reading or writing any slot; no table -> RETURN_ERR; a callback that differs from the one registered at apIndex -> RETURN_ERR and the slot unchanged; the same callback (NULL matches an
 * empty slot) -> RETURN_OK and the slot is NULL afterwards; no other slot, neighbouring member or the guard slab is touched.  No crash case is expected.
 */
#include "hwr_wru.h"
#include <limits.h>

/* name, ap_index, registered, passed, no_table, last */
hwr_wru_case_t sg_wifi_hal_RMBeaconRequestCallbackUnregister_suite[] = {
	{ "idx0_matching_a",            0, 1, 1, 0, 0 },
	{ "idx1_matching_b",            1, 2, 2, 0, 0 },
	{ "idx7_matching_a",            7, 1, 1, 0, 0 },
	{ "idx14_last_valid_matching",  14, 2, 2, 0, 0 },
	{ "idx0_mismatch_b_for_a",      0, 1, 2, 0, 0 },
	{ "idx14_mismatch_a_for_b",     14, 2, 1, 0, 0 },
	{ "idx3_null_passed_registered",3, 1, 0, 0, 0 },
	{ "idx3_callback_passed_empty", 3, 0, 1, 0, 0 },
	{ "idx3_null_passed_empty_slot",3, 0, 0, 0, 0 },
	{ "idx15_first_invalid_a",      15, 0, 1, 0, 0 },
	{ "idx15_first_invalid_null",   15, 0, 0, 0, 0 },
	{ "idx16",                      16, 0, 1, 0, 0 },
	{ "idx100",                     100, 0, 1, 0, 0 },
	{ "idx_uint_max",               UINT_MAX, 0, 0, 0, 0 },
	{ "idx_int_min_as_unsigned",    0x80000000u, 0, 1, 0, 0 },
	{ "idx15_invalid_and_no_table", 15, 0, 1, 1, 0 },
	{ "table_not_available_idx0",   0, 1, 1, 1, 0 },
	{ "table_not_available_idx14",  14, 0, 0, 1, 0 },
	{ NULL }
};

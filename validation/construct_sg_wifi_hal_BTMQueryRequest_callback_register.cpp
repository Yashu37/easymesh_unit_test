/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_BTMQueryRequest_callback_register
 *
 * wifi_hal_BTMQueryRequest_callback_register(apIndex, btmQueryCallback, btmResponseCallback).  Inputs crossed: apIndex 0 / 1 / 7 / 14 (valid, last valid) and 15 / 16 / 100 / UINT_MAX (out of range); callbacks
 * registered before none / A / B; callbacks passed NULL / A / B in every query x response combination that matters; the callbacks table available / not available.  The other slots hold callback C.
 * Expected (CORRECT behaviour): apIndex >= 15 -> RETURN_ERR without reading or writing any slot; no table -> RETURN_ERR; otherwise RETURN_OK and BOTH callbacks of btm_callback[apIndex] hold exactly the values
 * passed (a NULL replaces a registered one); no other slot, neighbouring member or the guard slab is touched.  No crash case is expected.
 */
#include "hwr_wbq.h"
#include <limits.h>

/* name, ap_index, old_q, old_r, new_q, new_r, no_table, last */
hwr_wbq_case_t sg_wifi_hal_BTMQueryRequest_callback_register_suite[] = {
	{ "idx0_register_both",          0, 0, 0, 1, 1, 0, 0 },
	{ "idx1_register_both_b",        1, 0, 0, 2, 2, 0, 0 },
	{ "idx7_mixed_a_b",              7, 0, 0, 1, 2, 0, 0 },
	{ "idx14_last_valid",            14, 0, 0, 2, 1, 0, 0 },
	{ "idx3_replace_both",           3, 1, 1, 2, 2, 0, 0 },
	{ "idx3_replace_query_only_resp_null", 3, 1, 1, 2, 0, 0, 0 },
	{ "idx3_replace_response_only_query_null", 3, 2, 2, 0, 1, 0, 0 },
	{ "idx3_null_clears_both",       3, 1, 2, 0, 0, 0, 0 },
	{ "idx3_null_on_empty",          3, 0, 0, 0, 0, 0, 0 },
	{ "idx3_same_callbacks_again",   3, 1, 1, 1, 1, 0, 0 },
	{ "idx15_first_invalid",         15, 0, 0, 1, 1, 0, 0 },
	{ "idx16",                       16, 0, 0, 1, 1, 0, 0 },
	{ "idx100",                      100, 0, 0, 2, 2, 0, 0 },
	{ "idx_uint_max",                UINT_MAX, 0, 0, 1, 1, 0, 0 },
	{ "idx_0x80000000",              0x80000000u, 0, 0, 1, 1, 0, 0 },
	{ "idx15_invalid_and_no_table",  15, 0, 0, 1, 1, 1, 0 },
	{ "table_not_available_idx0",    0, 1, 1, 2, 2, 1, 0 },
	{ "table_not_available_idx14",   14, 0, 0, 0, 0, 1, 0 },
	{ NULL }
};

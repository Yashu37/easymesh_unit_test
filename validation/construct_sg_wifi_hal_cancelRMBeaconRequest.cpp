/*
 * UNIT TEST (input constructor): construct_sg_wifi_hal_cancelRMBeaconRequest
 *
 * wifi_hal_cancelRMBeaconRequest(apIndex, dialogToken).  Inputs crossed: apIndex 0 / 3 / 14 (last valid) / 15 (MAX_AP_INDEX) / 16 / 100 / UINT_MAX; dialogToken 0 / 1 / 5 / 31 / 32 / 37 / 63 / 64 / 127 / 255 /
 * 128+; the token's "requested" bit set on no / the own VAP / several VAPs; sender records for the token (none, own VAP, another VAP, two entries pointing at the same sending VAP); a second token set on the
 * same VAP (to see that bits are independent).  The tables are preset with CORRECT 64-bit bit operations and compared with the CORRECT model: apIndex >= 15 -> WIFI_HAL_INVALID_ARGUMENTS and nothing changed;
 * otherwise WIFI_HAL_SUCCESS; the sender record of apIndex for the token is cleared; the "requested" bit of the sending VAP is cleared unless another VAP still has a record pointing at it; no other bit or
 * record changes; the lock is released.  (Tokens with bit position >= 32 in their 64-bit word are expected to fail on the original: wrong behaviour, no abort.)
 */
#include "hwr_wcb.h"
#include <limits.h>

#define NS { -1, -1, -1 }
#define V(n) (1 << (n))
/* name, apIndex, token, bits_mask, s_orig[3], s_sent[3], other_token, last */
hwr_wcb_case_t sg_wifi_hal_cancelRMBeaconRequest_suite[] = {
	/* ---- apIndex ---- */
	{ "apindex_15_invalid",       15,  5, V(3), NS, NS, -1, 0 },
	{ "apindex_16_invalid",       16,  5, V(3), NS, NS, -1, 0 },
	{ "apindex_100_invalid",     100,  5, V(3), NS, NS, -1, 0 },
	{ "apindex_uint_max",   UINT_MAX,  5, V(3), NS, NS, -1, 0 },
	{ "apindex_0_valid",           0,  5, V(0), NS, NS, -1, 0 },
	{ "apindex_14_last_valid",    14,  5, V(14), NS, NS, -1, 0 },
	/* ---- no sender record ---- */
	{ "token_5_own_bit_cleared",   3,  5, V(3), NS, NS, -1, 0 },
	{ "token_not_requested",       3,  5, 0, NS, NS, -1, 0 },
	{ "token_0",                   2,  0, V(2), NS, NS, -1, 0 },
	{ "token_1",                   2,  1, V(2), NS, NS, -1, 0 },
	{ "token_31",                  2, 31, V(2), NS, NS, -1, 0 },
	{ "token_other_vaps_keep_bits",4,  9, V(4)|V(5)|V(6), NS, NS, -1, 0 },
	{ "token_other_token_kept_5_and_9", 1, 5, V(1), NS, NS, 9, 0 },
	{ "token_other_token_kept_9_and_5", 1, 9, V(1), NS, NS, 5, 0 },
	/* ---- sender records / MLO ---- */
	{ "sender_other_vap_cleared", 3, 12, V(7), { 3,-1,-1 }, { 7,-1,-1 }, -1, 0 },
	{ "sender_other_vap_bit_of_own_vap_kept", 3, 12, V(3)|V(7), { 3,-1,-1 }, { 7,-1,-1 }, -1, 0 },
	{ "sender_shared_by_second_vap_keeps_bit", 3, 12, V(7), { 3, 5,-1 }, { 7, 7,-1 }, -1, 0 },
	{ "sender_own_vap_record",   4, 20, V(4), { 4,-1,-1 }, { 4,-1,-1 }, -1, 0 },
	{ "sender_other_record_points_to_own_vap_keeps_bit", 4, 20, V(4), { 9,-1,-1 }, { 4,-1,-1 }, -1, 0 },
	{ "sender_two_independent_records", 2, 40, V(2)|V(8), { 2, 6,-1 }, { 2, 8,-1 }, -1, 0 },
	/* ---- tokens with the 64-bit word position >= 32: reset_bit_u8() computes 1 << n on an int ---- */
	{ "token_32",                  2, 32, V(2), NS, NS, -1, 0 },
	{ "token_37",                  2, 37, V(2), NS, NS, -1, 0 },
	{ "token_63",                  2, 63, V(2), NS, NS, -1, 0 },
	{ "token_64",                  2, 64, V(2), NS, NS, -1, 0 },
	{ "token_127",                 2,127, V(2), NS, NS, -1, 0 },
	{ "token_255",                 2,255, V(2), NS, NS, -1, 0 },
	{ "token_37_other_token_5_kept", 1, 37, V(1), NS, NS, 5, 0 },
	{ "token_5_other_token_37_kept", 1,  5, V(1), NS, NS, 37, 0 },
	{ "token_31_other_token_40_kept", 1, 31, V(1), NS, NS, 40, 0 },
	{ NULL }
};

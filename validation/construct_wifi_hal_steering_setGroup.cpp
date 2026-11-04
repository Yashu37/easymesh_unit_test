/*
 * UNIT TEST (input constructor): construct_wifi_hal_steering_setGroup
 *
 * wifi_hal_steering_setGroup(steeringgroupIndex, cfg_2, cfg_5) validates the group index (< 8) and both config
 * pointers, then under steering_data_lock stores the group (index, enable = true, bm_group_info[0] = *cfg_2,
 * bm_group_info[1] = *cfg_5, the rest zeroed), sets the deny-mode MAC filter on the two APs with
 * steering_set_acl_mode() and logs the configuration.
 *
 * steering_set_acl_mode is a stub (below): it records (apIndex, mode) and fails for the APs the case asks for.
 * The runner fills every group with a 0x5C canary before the call, so a write outside the target group, or a
 * write after a validation failure, is visible.
 * Inputs crossed: every group 0..7, invalid groups 8, 9, 255, INT_MAX, UINT_MAX, NULL cfg_2 / cfg_5 / both
 * (valid and invalid group), extreme config values (apIndex -1 / 0 / INT_MAX / INT_MIN, UINT_MAX intervals),
 * cfg_2 and cfg_5 being the same pointer, steering_set_acl_mode failing for cfg_2's AP, cfg_5's AP or both, repeated
 * calls, and the log lines.  Expected result is the SAFE contract: a group whose deny-mode filter could not be
 * set is not reported as set (RETURN_ERR, group disabled).  A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gsg.h"

hwr_gsg_rec_t hwr_gsg_rec;
#define NOFAIL 0x7ABCDEF1       /* sentinel: no AP fails (-1 is a legal apIndex value) */
static int g_fail_a = NOFAIL, g_fail_b = NOFAIL;

extern "C" int steering_set_acl_mode(uint32_t apIndex, uint32_t mac_filter_mode)
{
	if (hwr_gsg_rec.calls < 4) { hwr_gsg_rec.ap[hwr_gsg_rec.calls] = apIndex; hwr_gsg_rec.mode[hwr_gsg_rec.calls] = mac_filter_mode; }
	hwr_gsg_rec.calls++;
	return ((int)apIndex == g_fail_a || (int)apIndex == g_fail_b) ? RETURN_ERR : RETURN_OK;
}
void hwr_gsg_configure(int fail_ap_a, int fail_ap_b) { g_fail_a = fail_ap_a; g_fail_b = fail_ap_b; memset(&hwr_gsg_rec, 0, sizeof(hwr_gsg_rec)); }

#define C2  { 0, 10, 3, 20, 30 }
#define C5  { 1, 11, 4, 21, 31 }
/* name, group, cfg_2, cfg_5, null_mask, acl_fail_mask, calls, check_log, expected_ret, expected_enabled, state_unchanged */
#define G(i)  { "group_" #i, i, { 2 * i, 10 + i, 3, 20, 30 }, { 2 * i + 1, 11 + i, 4, 21, 31 }, 0, 0, 1, 0, 0, 1, 0 }
hwr_gsg_case_t wifi_hal_steering_setGroup_suite[] = {
	G(0), G(1), G(2), G(3), G(4), G(5), G(6), G(7),
	/* ---- invalid group: RETURN_ERR, nothing modified ---- */
	{ "group_8_invalid",        8,        C2, C5, 0, 0, 1, 0, -1, 0, 1 },
	{ "group_9_invalid",        9,        C2, C5, 0, 0, 1, 0, -1, 0, 1 },
	{ "group_255_invalid",      255,      C2, C5, 0, 0, 1, 0, -1, 0, 1 },
	{ "group_int_max_invalid",  INT_MAX,  C2, C5, 0, 0, 1, 0, -1, 0, 1 },
	{ "group_uint_max_invalid", UINT_MAX, C2, C5, 0, 0, 1, 0, -1, 0, 1 },
	/* ---- NULL configs: RETURN_ERR, nothing modified ---- */
	{ "cfg_2_null",             2, C2, C5, 1, 0, 1, 0, -1, 0, 1 },
	{ "cfg_5_null",             2, C2, C5, 2, 0, 1, 0, -1, 0, 1 },
	{ "both_cfg_null",          2, C2, C5, 3, 0, 1, 0, -1, 0, 1 },
	{ "cfg_null_and_group_invalid", 9, C2, C5, 3, 0, 1, 0, -1, 0, 1 },
	/* ---- config values are stored as given ---- */
	{ "ap_index_minus_1",       3, { -1, 1, 1, 1, 1 }, { -2, 1, 1, 1, 1 }, 0, 0, 1, 0, 0, 1, 0 },
	{ "ap_index_int_max_int_min", 3, { INT_MAX, 1, 1, 1, 1 }, { INT_MIN, 1, 1, 1, 1 }, 0, 0, 1, 0, 0, 1, 0 },
	{ "intervals_uint_max",     4, { 0, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX }, { 1, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX }, 0, 0, 1, 0, 0, 1, 0 },
	{ "all_zero_config",        4, { 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 }, 0, 0, 1, 0, 0, 1, 0 },
	{ "same_pointer_for_both_cfgs", 5, C2, C2, 4, 0, 1, 0, 0, 1, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3_same_group", 6, C2, C5, 0, 0, 3, 0, 0, 1, 0 },
	{ "log_has_steering_config_lines", 7, C2, C5, 0, 0, 1, 1, 0, 1, 0 },
	/* ---- the deny-mode MAC filter cannot be set on one of the APs (unknown VAP, STA VAP, user-configured filter mode ...) ---- */
	{ "acl_fails_for_cfg_2_ap",   0, C2, C5, 0, 1, 1, 0, -1, 0, 0 },
	{ "acl_fails_for_cfg_5_ap",   0, C2, C5, 0, 2, 1, 0, -1, 0, 0 },
	{ "acl_fails_for_both_aps",   0, C2, C5, 0, 3, 1, 0, -1, 0, 0 },
	{ "acl_fails_for_cfg_5_ap_group_7", 7, C2, C5, 0, 2, 1, 0, -1, 0, 0 },
	{ "acl_fails_for_cfg_2_ap_group_3", 3, { 4, 9, 9, 9, 9 }, { 5, 9, 9, 9, 9 }, 0, 1, 1, 0, -1, 0, 0 },
	{ NULL, 0, C2, C5, 0, 0, 0, 0, 0, 0, 0 }
};

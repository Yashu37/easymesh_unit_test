/*
 * UNIT TEST (input constructor): construct_platform_post_init
 *
 * platform_post_init(vap_map) (platform/banana-pi) adds the interfaces to the bridge: system("brctl addif brlan0 wifi0"),
 * ...wifi1, ...wifi2, and returns 0.  vap_map is never used.  Inputs crossed: no failure; each of the three commands
 * failing alone; the first two / all three failing; the failure status values system() can return (-1 = fork failed,
 * 256 = brctl exit 1, 32512 = shell exit 127 = brctl not found); vap_map NULL and vap_map pointing to a fully poisoned slab
 * (the function must not read it); two calls in a row (a second call after a failed first one).
 * Expected = the SAFE contract: always all three commands in order, a failure is logged and makes the function return
 * -1, success returns 0, vap_map untouched.  The unfixed function returns 0 and logs nothing for a failure, so those rows
 * FAIL (finding).
 */
#include "hwr_ppo.h"

hwr_ppo_rec_t hwr_ppo_rec;
extern "C" int hwr_ppo_system(const char *cmd)
{
	int idx = hwr_ppo_rec.n++;

	if (idx < 8) snprintf(hwr_ppo_rec.cmd[idx], sizeof(hwr_ppo_rec.cmd[idx]), "%s", cmd);
	return (hwr_ppo_rec.fail_mask >> idx) & 1 ? hwr_ppo_rec.fail_status : 0;
}

/* name, fail_mask, fail_status, map_null, calls, expected_ret, expect_log_fail */
hwr_ppo_case_t platform_post_init_suite[] = {
	{ "all_ok_map_null",               0x0, 0,     1, 1,  0, 0 },
	{ "all_ok_map_poisoned",           0x0, 0,     0, 1,  0, 0 },
	{ "all_ok_two_calls",              0x0, 0,     0, 2,  0, 0 },
	{ "wifi0_fails",                   0x1, 256,   0, 1, -1, 1 },
	{ "wifi1_fails",                   0x2, 256,   0, 1, -1, 1 },
	{ "wifi2_fails",                   0x4, 256,   0, 1, -1, 1 },
	{ "wifi0_and_wifi1_fail",          0x3, 256,   0, 1, -1, 2 },
	{ "wifi0_and_wifi2_fail",          0x5, 256,   1, 1, -1, 2 },
	{ "all_three_fail",                0x7, 256,   0, 1, -1, 3 },
	{ "fail_status_minus_1_fork",      0x1, -1,    0, 1, -1, 1 },
	{ "fail_status_127_not_found",     0x7, 32512, 0, 1, -1, 3 },
	{ "first_call_fails_second_ok",    0x7, 256,   0, 2,  0, 3 },
	{ "first_call_ok_second_fails",    0x38, 256,  0, 2, -1, 3 },
	{ NULL, 0, 0, 0, 0, 0, 0 }
};

/*
 * TEST RUNNER: wifi_hal_steering_setGroup_test
 *
 * The runner fills all 8 groups of g_wifi_hal with a 0x5C canary, builds the two config structures in
 * runner-owned slabs, POISONS their tails, calls the function, UNPOISONS and checks the result:
 *   hwr_cfg2_slab / hwr_cfg5_slab : [sizeof(wifi_steering_apConfig_t), end)   - the function copies exactly one config each
 *   hwr_log_buf                   : [HWR_LOG_USE, HWR_LOG_SZ)
 * and then verifies the stored group, the untouched groups (canary) and the steering_set_acl_mode calls.
 * The function is NOT modified.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "hwr_gsg.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_cfg2_slab[sizeof(wifi_steering_apConfig_t) + PADB];
static unsigned char hwr_cfg5_slab[sizeof(wifi_steering_apConfig_t) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_cfg2_slab[sizeof(wifi_steering_apConfig_t)], PADB);
	fn(&hwr_cfg5_slab[sizeof(wifi_steering_apConfig_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[220];

static void fill_cfg(wifi_steering_apConfig_t *c, const hwr_gsg_cfg_t *s)
{
	memset(c, 0, sizeof(*c));
	c->apIndex = s->ap; c->utilCheckIntervalSec = s->util_int; c->utilAvgCount = s->util_cnt;
	c->inactCheckIntervalSec = s->inact_int; c->inactCheckThresholdSec = s->inact_thr;
}

static int cfg_eq(const wifi_steering_apConfig_t *a, const wifi_steering_apConfig_t *b) { return !memcmp(a, b, sizeof(*a)); }

static int run_case(const hwr_gsg_case_t *t)
{
	wifi_steering_apConfig_t exp2, exp5;
	wifi_steering_apConfig_t *c2 = (t->null_mask & 1) ? NULL : (wifi_steering_apConfig_t *)hwr_cfg2_slab;
	wifi_steering_apConfig_t *c5 = (t->null_mask & 2) ? NULL : (t->null_mask & 4) ? c2 : (wifi_steering_apConfig_t *)hwr_cfg5_slab;
	hwr_gsg_world_t before;

	why[0] = 0;
	memset(hwr_cfg2_slab, 0, sizeof(hwr_cfg2_slab)); memset(hwr_cfg5_slab, 0, sizeof(hwr_cfg5_slab));
	fill_cfg((wifi_steering_apConfig_t *)hwr_cfg2_slab, &t->c2); fill_cfg((wifi_steering_apConfig_t *)hwr_cfg5_slab, &t->c5);
	exp2 = *(wifi_steering_apConfig_t *)hwr_cfg2_slab;
	exp5 = (t->null_mask & 4) ? exp2 : *(wifi_steering_apConfig_t *)hwr_cfg5_slab;

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_gsg_world.bm_steer_groups, 0x5C, sizeof(hwr_gsg_world.bm_steer_groups));
		memset(hwr_log_buf, 0, HWR_LOG_USE);
		before = hwr_gsg_world;
		hwr_gsg_configure((t->acl_fail_mask & 1) ? t->c2.ap : HWR_GSG_NOFAIL, (t->acl_fail_mask & 2) ? t->c5.ap : HWR_GSG_NOFAIL);
		poison_all(1);
		INT ret = hwr_wifi_hal_steering_setGroup(t->group, c2, c5);
		poison_all(0);

		if (ret != t->expected_ret) { snprintf(why, sizeof(why), "call %d returned %d, expected %d%s", i, ret, t->expected_ret, (ret == 0 && t->acl_fail_mask) ? " (MAC filter deny mode could not be set, but success reported)" : ""); return 0; }

		for (unsigned g = 0; g < 8; g++) {
			if (g == t->group && !t->state_unchanged) continue;
			if (memcmp(&hwr_gsg_world.bm_steer_groups[g], &before.bm_steer_groups[g], sizeof(hwr_bm_group_t))) { snprintf(why, sizeof(why), "group %u modified", g); return 0; }
		}
		if (t->state_unchanged) { if (hwr_gsg_rec.calls) { snprintf(why, sizeof(why), "steering_set_acl_mode called %d times after a validation failure", hwr_gsg_rec.calls); return 0; } continue; }

		hwr_bm_group_t *grp = &hwr_gsg_world.bm_steer_groups[t->group];
		if ((int)grp->group_enable != t->expected_enabled) { snprintf(why, sizeof(why), "group_enable = %u, expected %d%s", grp->group_enable, t->expected_enabled, (t->expected_enabled == 0 && grp->group_enable) ? " (group left enabled)" : ""); return 0; }
		if (t->expected_ret == 0) {
			if (grp->group_index != t->group) { snprintf(why, sizeof(why), "group_index %u", grp->group_index); return 0; }
			if (!cfg_eq(&grp->bm_group_info[0].config, &exp2)) { snprintf(why, sizeof(why), "bm_group_info[0] != cfg_2"); return 0; }
			if (!cfg_eq(&grp->bm_group_info[1].config, &exp5)) { snprintf(why, sizeof(why), "bm_group_info[1] != cfg_5"); return 0; }
			for (int k = 2; k < MAX_NUM_RADIOS; k++) { unsigned char *p = (unsigned char *)&grp->bm_group_info[k]; for (size_t z = 0; z < sizeof(hwr_bm_info_t); z++) if (p[z]) { snprintf(why, sizeof(why), "bm_group_info[%d] not zeroed", k); return 0; } }
			if (hwr_gsg_rec.calls != 2 || hwr_gsg_rec.ap[0] != (uint32_t)exp2.apIndex || hwr_gsg_rec.ap[1] != (uint32_t)exp5.apIndex || hwr_gsg_rec.mode[0] != (uint32_t)wifi_mac_filter_mode_black_list || hwr_gsg_rec.mode[1] != (uint32_t)wifi_mac_filter_mode_black_list) { snprintf(why, sizeof(why), "steering_set_acl_mode calls wrong (%d calls)", hwr_gsg_rec.calls); return 0; }
		}
	}
	if (t->check_log && (!strstr(hwr_log_buf, "Wi-Fi steering ApGroup 7 CFG: apidx=0, 10, 3, 20, 30") || !strstr(hwr_log_buf, "apidx=1, 11, 4, 21, 31"))) { snprintf(why, sizeof(why), "log lacks the cfg_2 steering line: '%.120s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_steering_setGroup(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_steering_setGroup_suite[i].test_name != NULL; i++) {
		hwr_gsg_case_t *test = &wifi_hal_steering_setGroup_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_steering_setGroup: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

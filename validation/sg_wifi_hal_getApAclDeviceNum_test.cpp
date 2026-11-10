/*
 * TEST RUNNER: sg_wifi_hal_getApAclDeviceNum_test
 *
 * test_sg_wifi_hal_getApAclDeviceNum() POISONS what the function must not touch, calls the handler and unpoisons: aclCount (an exact 4-byte heap block holding a sentinel) whenever the driver call fails or is not
 * made (the wrapper must not write it itself), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The driver stub writes *acl_count only on success, so a poisoned aclCount on the failure
 * paths proves the wrapper does not touch it.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, the driver call count / apIndex /
 * pointer, aclCount (reported count or sentinel), guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wgn.h"
#include <sanitizer/asan_interface.h>

#define SENTINEL 0xC0FFEEu
static char why[240];
static int ret_val;
static uint *cnt;

static int drv_made(const hwr_wgn_case_t *t) { return !t->null_count; }
static int expect_ok(const hwr_wgn_case_t *t) { return drv_made(t) && t->drv_ret == 0; }

static void poison(int on, const hwr_wgn_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (cnt && !expect_ok(t)) fn(cnt, sizeof(*cnt));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_getApAclDeviceNum(const hwr_wgn_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_getApAclDeviceNum(t->apIndex, t->null_count ? NULL : cnt);
	poison(0, t);
}

static int check(const hwr_wgn_case_t *t)
{
	const hwr_wgn_world_t *w = &hwr_wgn_world;
	int want = expect_ok(t) ? RETURN_OK : RETURN_ERR;

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->calls != (drv_made(t) ? 1 : 0)) { snprintf(why, sizeof(why), "driver call made %d times, expected %d", w->calls, drv_made(t) ? 1 : 0); return 0; }
	if (drv_made(t)) {
		if (w->last_vap_index != t->apIndex) { snprintf(why, sizeof(why), "driver got apIndex %d, expected %d", w->last_vap_index, t->apIndex); return 0; }
		if (w->last_ptr != cnt) { snprintf(why, sizeof(why), "driver got another pointer than aclCount"); return 0; }
	}
	if (cnt) {
		uint want_cnt = expect_ok(t) ? t->drv_value : SENTINEL;
		if (*cnt != want_cnt) { snprintf(why, sizeof(why), "aclCount is %u, expected %u", *cnt, want_cnt); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_getApAclDeviceNum(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_getApAclDeviceNum_suite[i].test_name != NULL; i++) {
			hwr_wgn_case_t *test = &sg_wifi_hal_getApAclDeviceNum_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_wgn_world, 0, sizeof(hwr_wgn_world));
			hwr_wgn_world.ret = test->drv_ret; hwr_wgn_world.value = test->drv_value;
			cnt = (uint *)malloc(sizeof(uint)); *cnt = SENTINEL;
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_getApAclDeviceNum(test);

			int ok = check(test);
			free(cnt); cnt = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_getApAclDeviceNum: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

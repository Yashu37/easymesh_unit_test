/*
 * TEST RUNNER: sg_wifi_hal_getInterfaceMap_test
 *
 * test_sg_wifi_hal_getInterfaceMap() POISONS what the function must not touch, calls the handler and unpoisons; run_all_tests compares the result.  The runner owns
 * the output map: a slab of 42 entries (176 bytes each, canary 0x5A) with the map at entry 1 and EXACTLY size entries long; the entry before and everything after the
 * map is POISONED during the call (any write beyond the copied entries aborts under ASan), together with the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).
 * Checks: return value; *if_map_size == size (also on the error path); the copied entries equal the table on success and the map is still the canary on the error path;
 * the "Invalid buffer size" log appears exactly on the error path; one size query per call on the error path.  Rows with last = 1 crash the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_gim.h"
#include <sanitizer/asan_interface.h>

#define ES sizeof(hwr_gim_entry_t)
#define OFFE 1
static unsigned char slab[(HWR_GIM_MAX_TABLE + 2) * sizeof(hwr_gim_entry_t)];
static unsigned int out_size;
static char why[200];

static void poison(int on, const hwr_gim_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->map_mode == 1) {
		fn(&slab[0], OFFE * ES);
		fn(&slab[(OFFE + t->size) * ES], sizeof(slab) - (OFFE + t->size) * ES);
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_getInterfaceMap(const hwr_gim_case_t *t)
{
	hwr_gim_entry_t *map = t->map_mode == 0 ? NULL : t->map_mode == 1 ? (hwr_gim_entry_t *)&slab[OFFE * ES] : (hwr_gim_entry_t *)(unsigned long)0xdeadbeefUL;
	unsigned int *sp = t->size_mode ? &out_size : NULL;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_getInterfaceMap(map, t->max_entries, sp);
	poison(0, t);
	return ret;
}

static int check(const hwr_gim_case_t *t, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->size_mode && out_size != t->size) { snprintf(why, sizeof(why), "*if_map_size = %u, expected %u", out_size, t->size); return 0; }
	int err = t->expected_ret != 0;
	int has = strstr(hwr_log_buf, "Invalid buffer size") != NULL;
	if (err != has) { snprintf(why, sizeof(why), "error log %s, expected %s", has ? "present" : "missing", err ? "present" : "absent"); return 0; }
	if (t->map_mode == 1) {
		for (size_t k = 0; k < sizeof(slab); k++) {
			int in_map = k >= OFFE * ES && k < (OFFE + t->size) * ES;
			unsigned char want = (in_map && !err) ? ((unsigned char *)hwr_gim_world.table)[k - OFFE * ES] : 0x5A;
			if (slab[k] != want) { snprintf(why, sizeof(why), "map slab byte %zu is 0x%02x, expected 0x%02x", k, slab[k], want); return 0; }
		}
		if (!err && hwr_gim_world.map_calls != t->calls) { snprintf(why, sizeof(why), "copy called %d times, expected %d", hwr_gim_world.map_calls, t->calls); return 0; }
		if (err && hwr_gim_world.map_calls != 0) { snprintf(why, sizeof(why), "entries copied although the buffer is too small"); return 0; }
	}
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_getInterfaceMap(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_getInterfaceMap_suite[i].test_name != NULL; i++) {
		hwr_gim_case_t *test = &sg_wifi_hal_getInterfaceMap_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_gim_world, 0, sizeof(hwr_gim_world));
		hwr_gim_world.size = test->size;
		for (unsigned e = 0; e < HWR_GIM_MAX_TABLE; e++) {
			hwr_gim_entry_t *x = &hwr_gim_world.table[e];
			x->phy_index = e; x->rdk_radio_index = e / 2; x->vlan_id = 100 + e; x->index = e;
			snprintf(x->interface_name, sizeof(x->interface_name), "wl%u.%u", e / 4, e % 4);
			snprintf(x->mld_interface_name, sizeof(x->mld_interface_name), "mld%u", e);
			snprintf(x->bridge_name, sizeof(x->bridge_name), "br%u", e);
			snprintf(x->vap_name, sizeof(x->vap_name), "vap_%u", e);
		}
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(slab, 0x5A, sizeof(slab));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		out_size = 0xFFFFFFFFu;

		int ret = test_sg_wifi_hal_getInterfaceMap(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_getInterfaceMap: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

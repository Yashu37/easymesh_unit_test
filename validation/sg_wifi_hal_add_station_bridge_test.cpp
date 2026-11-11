/*
 * TEST RUNNER: sg_wifi_hal_add_station_bridge_test
 *
 * test_sg_wifi_hal_add_station_bridge() POISONS what the function must not touch, calls the handler and unpoisons: the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The two names are exact heap blocks (their bytes are read only by the helper stubs, which model the real callees), so a helper reading beyond the terminator is a
 * heap-buffer-overflow.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, helpers called in the order remove -> create with the
 * unchanged pointers (or not at all for a NULL name), guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wsb.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static char *ifname, *brname;

static char *mk(int mode)
{
	const char *s = mode == 1 ? "wlan0" : mode == 2 ? "abcdefghijklmno" : mode == 3 ? "" : NULL;
	char *p;
	if (!s) return NULL;
	p = (char *)malloc(strlen(s) + 1);
	strcpy(p, s);
	return p;
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wsb_world.unrelated, sizeof(hwr_wsb_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_add_station_bridge(void)
{
	poison(1);
	ret_val = hwr_sg_wifi_hal_add_station_bridge(ifname, brname);
	poison(0);
}

static int check(const hwr_wsb_case_t *t)
{
	const hwr_wsb_world_t *w = &hwr_wsb_world;
	int null_arg = (t->if_mode == 0 || t->br_mode == 0);
	int want = null_arg ? RETURN_ERR : (t->cr_ret == 0 ? 0 : RETURN_ERR);
	int want_calls = null_arg ? 0 : 1;

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->rm_calls != want_calls || w->cr_calls != want_calls) { snprintf(why, sizeof(why), "helpers called remove %d / create %d times, expected %d each", w->rm_calls, w->cr_calls, want_calls); return 0; }
	if (want_calls) {
		if (w->rm_order != 1 || w->cr_order != 2) { snprintf(why, sizeof(why), "wrong call order (remove %d, create %d)", w->rm_order, w->cr_order); return 0; }
		if (w->rm_name != ifname || w->cr_if != ifname || w->cr_br != brname) { snprintf(why, sizeof(why), "name pointers not forwarded unchanged"); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wsb_case_t *t)
{
	memset(&hwr_wsb_world, 0, sizeof(hwr_wsb_world));
	hwr_wsb_world.rm_ret = t->rm_ret; hwr_wsb_world.cr_ret = t->cr_ret;
	ifname = mk(t->if_mode); brname = mk(t->br_mode);
}

extern "C" void run_all_tests_sg_wifi_hal_add_station_bridge(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_add_station_bridge_suite[i].test_name != NULL; i++) {
			hwr_wsb_case_t *test = &sg_wifi_hal_add_station_bridge_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_add_station_bridge();

			int ok = check(test);
			free(ifname); free(brname); ifname = brname = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_add_station_bridge: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

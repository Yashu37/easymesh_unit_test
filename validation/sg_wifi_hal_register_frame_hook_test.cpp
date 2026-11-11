/*
 * TEST RUNNER: sg_wifi_hal_register_frame_hook_test
 *
 * test_sg_wifi_hal_register_frame_hook() POISONS what the function must not touch, calls the handler and unpoisons, once per registration: every frame_hooks_fn[] slot except the one the call is allowed to
 * write (the slot at num_hooks), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  hwr_wrf_hooks is a stand-alone global with an ASan redzone, so a write past frame_hooks_fn[MAX_APPS-1] is
 * a global-buffer-overflow.  run_all_tests compares the table with a reference model of the CORRECT behaviour (see the construct file): stored callbacks, num_hooks, earlier slots kept, guard slab unchanged.
 * Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wrf.h"
#include <sanitizer/asan_interface.h>

static char why[240];

static wifi_hal_frame_hook_fn_t fn_for(int k) { return (k % 2 == 0) ? hwr_wrf_hook_b : hwr_wrf_hook_a; }

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	unsigned n = hwr_wrf_hooks.num_hooks;

	/* the call may write only frame_hooks_fn[num_hooks]; num_hooks itself is read and written */
	/* unpoison covers every slot (num_hooks has moved by then) */
	for (unsigned i = 0; i < MAX_APPS; i++) if (!on || i != n) fn(&hwr_wrf_hooks.frame_hooks_fn[i], sizeof(hwr_wrf_hooks.frame_hooks_fn[i]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per registration) */
static void test_sg_wifi_hal_register_frame_hook(const hwr_wrf_case_t *t)
{
	for (int k = 0; k < t->calls; k++) {
		poison(1);
		hwr_sg_wifi_hal_register_frame_hook(fn_for(k));
		poison(0);
	}
}

static int check(const hwr_wrf_case_t *t)
{
	unsigned n = t->start_n;

	if (n > MAX_APPS) n = MAX_APPS;     /* the correct code never lets num_hooks exceed the table */
	unsigned want_n = t->start_n;
	wifi_hal_frame_hook_fn_t want[MAX_APPS];
	for (unsigned i = 0; i < MAX_APPS; i++) want[i] = i < t->start_n ? hwr_wrf_hook_a : NULL;
	for (int k = 0; k < t->calls; k++) if (want_n < MAX_APPS) want[want_n++] = fn_for(k);
	if (t->start_n > MAX_APPS) want_n = MAX_APPS;      /* an impossible start state is clamped by the model */

	if (hwr_wrf_hooks.num_hooks != want_n) { snprintf(why, sizeof(why), "num_hooks is %u, expected %u", hwr_wrf_hooks.num_hooks, want_n); return 0; }
	for (unsigned i = 0; i < MAX_APPS; i++)
		if (hwr_wrf_hooks.frame_hooks_fn[i] != (i < n || i < want_n ? want[i] : NULL)) { snprintf(why, sizeof(why), "frame_hooks_fn[%u] wrong", i); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wrf_case_t *t)
{
	memset(&hwr_wrf_hooks, 0, sizeof(hwr_wrf_hooks));
	hwr_wrf_hooks.num_hooks = t->start_n;
	for (unsigned i = 0; i < MAX_APPS && i < t->start_n; i++) hwr_wrf_hooks.frame_hooks_fn[i] = hwr_wrf_hook_a;
}

extern "C" void run_all_tests_sg_wifi_hal_register_frame_hook(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_register_frame_hook_suite[i].test_name != NULL; i++) {
			hwr_wrf_case_t *test = &sg_wifi_hal_register_frame_hook_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_register_frame_hook(test);

			int ok = check(test);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_register_frame_hook: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

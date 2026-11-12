/*
 * TEST RUNNER: sg_wifi_authenticator_run_test
 *
 * test_sg_wifi_authenticator_run() POISONS what the function must not touch, calls the handler and unpoisons (once per call): the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the recorded eloop_run calls with a reference model of the CORRECT behaviour (see the construct file).  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_war.h"
#include <sanitizer/asan_interface.h>

static char why[300];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_war_world.unrelated, sizeof(hwr_war_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_authenticator_run(const hwr_war_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		hwr_war_world.eloop_iterations = t->iterations;
		poison(1);
		hwr_sg_wifi_authenticator_run();
		poison(0);
		if (hwr_war_world.in_loop) hwr_war_world.returned_inside_loop = 1;
	}
}

static int check(const hwr_war_case_t *t)
{
	const hwr_war_world_t *w = &hwr_war_world;

	if (w->eloop_calls != t->calls) { snprintf(why, sizeof(why), "eloop_run ran %d times, expected %d", w->eloop_calls, t->calls); return 0; }
	if (w->returned_inside_loop) { snprintf(why, sizeof(why), "returned while the event loop was still running"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_authenticator_run(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_authenticator_run_suite[i].test_name != NULL; i++) {
			hwr_war_case_t *test = &sg_wifi_authenticator_run_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_war_world, 0, sizeof(hwr_war_world));
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_authenticator_run(test);

			if (check(test)) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_authenticator_run: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

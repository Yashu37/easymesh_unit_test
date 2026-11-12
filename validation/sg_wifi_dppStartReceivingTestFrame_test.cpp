/*
 * TEST RUNNER: sg_wifi_dppStartReceivingTestFrame_test
 *
 * test_sg_wifi_dppStartReceivingTestFrame() POISONS what the function must not touch, calls the handler and unpoisons (once per call): the world's unrelated members, the guard slab and the log
 * slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The thread id is a local of the function (stack red zone).  run_all_tests compares the recorded pthread_create calls with a reference model of the CORRECT
 * behaviour (see the construct file): number of calls, thread-id pointer, attribute, start routine and argument for each call.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wtq.h"
#include <sanitizer/asan_interface.h>

static char why[240];

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wtq_world.unrelated, sizeof(hwr_wtq_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_dppStartReceivingTestFrame(const hwr_wtq_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		poison(1);
		hwr_sg_wifi_dppStartReceivingTestFrame();
		poison(0);
	}
}

static int check(const hwr_wtq_case_t *t)
{
	const hwr_wtq_world_t *w = &hwr_wtq_world;

	if (w->create_calls != t->calls) { snprintf(why, sizeof(why), "pthread_create ran %d times, expected %d", w->create_calls, t->calls); return 0; }
	for (int n = 0; n < t->calls; n++) {
		if (w->tid_ptr[n] == NULL) { snprintf(why, sizeof(why), "call %d: NULL thread-id pointer", n); return 0; }
		if (w->attr[n] != NULL) { snprintf(why, sizeof(why), "call %d: attributes %p, expected NULL", n, (const void *)w->attr[n]); return 0; }
		if (w->routine[n] != wifi_dppTestFrameHandler) { snprintf(why, sizeof(why), "call %d: wrong start routine", n); return 0; }
		if (w->arg[n] != NULL) { snprintf(why, sizeof(why), "call %d: argument %p, expected NULL", n, w->arg[n]); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_dppStartReceivingTestFrame(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_dppStartReceivingTestFrame_suite[i].test_name != NULL; i++) {
			hwr_wtq_case_t *test = &sg_wifi_dppStartReceivingTestFrame_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_wtq_world, 0, sizeof(hwr_wtq_world));
			for (int n = 0; n < 5; n++) hwr_wtq_world.script[n] = test->script[n];
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_dppStartReceivingTestFrame(test);

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
	printf("\nwifi_dppStartReceivingTestFrame: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

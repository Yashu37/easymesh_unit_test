/*
 * TEST RUNNER: sg_wifi_setGASConfiguration_test
 *
 * test_sg_wifi_setGASConfiguration() POISONS what the function must not touch, calls the handler and unpoisons (once per call): the world's unrelated members, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The input struct is an exactly sized heap block (over-read reported by ASan) and gasCfg[] is a one-element static (an index beyond it is caught by the global red zone).
 * run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, stored configuration, apply hook calls / argument.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wgc.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static INT rets[2];
static wifi_GASConfiguration_t *in[2];
static unsigned char want_cfg[sizeof(wifi_GASConfiguration_t)];
static int want_applies; static const void *want_arg;

static void fill(wifi_GASConfiguration_t *c, int pattern)
{
	unsigned char *p = (unsigned char *)c;
	for (size_t i = 0; i < sizeof(*c); i++) p[i] = pattern == 0 ? 0 : pattern == 1 ? 1 : pattern == 3 ? 0xFF : (unsigned char)(i * 13 + 5);
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_wgc_world.unrelated, sizeof(hwr_wgc_world.unrelated));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison (once per call) */
static void test_sg_wifi_setGASConfiguration(const hwr_wgc_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		poison(1);
		rets[n] = hwr_sg_wifi_setGASConfiguration(t->id, in[n]);
		poison(0);
	}
}

static int check(const hwr_wgc_case_t *t)
{
	for (int n = 0; n < t->calls; n++) {
		INT want = (t->input_null || t->id != 0) ? RETURN_ERR : RETURN_OK;
		if (rets[n] != want) { snprintf(why, sizeof(why), "call %d returned %d, expected %d", n, rets[n], want); return 0; }
		if (want == RETURN_OK) { memcpy(want_cfg, in[n], sizeof(want_cfg)); want_applies++; want_arg = in[n]; }
	}
	if (memcmp(hwr_wgc_cfg(), want_cfg, sizeof(want_cfg)) != 0) { snprintf(why, sizeof(why), "stored configuration differs from the expected one"); return 0; }
	if (hwr_wgc_world.apply_calls != want_applies) { snprintf(why, sizeof(why), "apply hook ran %d times, expected %d", hwr_wgc_world.apply_calls, want_applies); return 0; }
	if (want_applies && hwr_wgc_world.apply_arg != want_arg) { snprintf(why, sizeof(why), "apply hook got another pointer"); return 0; }
	if (want_applies && memcmp(hwr_wgc_world.apply_copy, want_cfg, sizeof(want_cfg)) != 0) { snprintf(why, sizeof(why), "apply hook saw a different configuration"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_setGASConfiguration(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_setGASConfiguration_suite[i].test_name != NULL; i++) {
			hwr_wgc_case_t *test = &sg_wifi_setGASConfiguration_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(&hwr_wgc_world, 0, sizeof(hwr_wgc_world));
			memset(hwr_wgc_cfg(), 0x77, sizeof(wifi_GASConfiguration_t));
			memset(want_cfg, 0x77, sizeof(want_cfg)); want_applies = 0; want_arg = NULL;
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			for (int n = 0; n < 2; n++) {
				in[n] = NULL;
				if (!test->input_null && n < test->calls) {
					in[n] = (wifi_GASConfiguration_t *)malloc(sizeof(wifi_GASConfiguration_t));
					fill(in[n], n == 0 ? test->pattern : (test->pattern + 1) % 4);
				}
			}

			test_sg_wifi_setGASConfiguration(test);

			int ok = check(test);
			for (int n = 0; n < 2; n++) free(in[n]);
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_setGASConfiguration: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

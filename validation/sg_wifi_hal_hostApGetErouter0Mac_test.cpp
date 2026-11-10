/*
 * TEST RUNNER: sg_wifi_hal_hostApGetErouter0Mac_test
 *
 * test_sg_wifi_hal_hostApGetErouter0Mac() POISONS what the function must not touch, calls the handler and unpoisons.  The output is either a heap buffer of exactly 18 bytes
 * (ASan redzones) or a 64-byte slab (preset to the row's fill byte) whose bytes after the first 18 are POISONED during the call; the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value; on success out == "01:23:12:44:65:ab" and, in the slab, the bytes after the NUL are still the fill byte; on NULL
 * nothing is written; the log slot and the guard slab are unchanged (the function does not log).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wem.h"
#include <sanitizer/asan_interface.h>

#define MAC "01:23:12:44:65:ab"
static unsigned char slab[64];
static char log_before[HWR_LOG_SZ];
static char why[200];

static void poison(int on, const hwr_wem_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->out_mode == 2) fn(&slab[18], sizeof(slab) - 18);
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_hostApGetErouter0Mac(const hwr_wem_case_t *t, char *out)
{
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_hostApGetErouter0Mac(out);
	poison(0, t);
	return ret;
}

static int check(const hwr_wem_case_t *t, const char *out, int ret)
{
	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (t->out_mode != 0 && memcmp(out, MAC, sizeof(MAC)) != 0) { snprintf(why, sizeof(why), "out is not the expected MAC string with its NUL"); return 0; }
	if (t->out_mode == 2) for (size_t k = 18; k < sizeof(slab); k++) if (slab[k] != t->fill) { snprintf(why, sizeof(why), "slab byte %zu past the MAC modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, sizeof(why), "the log was modified (the function does not log)"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_hostApGetErouter0Mac(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_hostApGetErouter0Mac_suite[i].test_name != NULL; i++) {
		hwr_wem_case_t *test = &sg_wifi_hal_hostApGetErouter0Mac_suite[i];
		char *out = NULL, *heap = NULL;

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
		memset(slab, test->fill, sizeof(slab));
		if (test->out_mode == 1) { heap = (char *)malloc(18); memset(heap, test->fill, 18); out = heap; }
		else if (test->out_mode == 2) out = (char *)slab;

		int ret = test_sg_wifi_hal_hostApGetErouter0Mac(test, out);

		if (check(test, out, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		free(heap);
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_hostApGetErouter0Mac: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

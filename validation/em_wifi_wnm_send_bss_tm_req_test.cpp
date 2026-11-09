/*
 * TEST RUNNER: em_wifi_wnm_send_bss_tm_req_test
 *
 * Same shape as the other *_test.cpp runners: test_em_wifi_wnm_send_bss_tm_req() POISONS what the function must not touch, calls the handler and unpoisons;
 * run_all_tests compares the result.  When the case passes pointers (mode 1) they all point into one 256-byte runner slab that is fully POISONED during the call
 * (the stub must not read or write through any of them: any access aborts under ASan); mode 0 passes NULL, mode 2 a dangling pointer.  The guard slab and the log
 * slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value 0; the slab bytes unchanged; the guard slab unchanged; the whole log unchanged
 * (the function does not log).
 */
#include <stdio.h>
#include <string.h>
#include "hwr_ewb.h"
#include <sanitizer/asan_interface.h>

static unsigned char slab[256];
static char log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_ewb_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->ptr_mode == 1) fn(slab, sizeof(slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what the function returned (last call) */
int test_em_wifi_wnm_send_bss_tm_req(const hwr_ewb_case_t *t)
{
	unsigned char *p = t->ptr_mode == 0 ? NULL : t->ptr_mode == 1 ? slab : (unsigned char *)(unsigned long)0xdeadbeefUL;
	u8 s = (u8)t->small;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++)
		ret = hwr_em_wifi_wnm_send_bss_tm_req((struct wifi_interface_info_t *)p, (struct sta_info *)p, s, s, t->timer, s, p,
			(const char *)p, p, t->len, p, t->len);
	poison(0, t);
	return ret;
}

static int check(const hwr_ewb_case_t *t, int ret, char *why, size_t wn)
{
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (size_t k = 0; k < sizeof(slab); k++) if (slab[k] != 0x6B) { snprintf(why, wn, "slab byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_em_wifi_wnm_send_bss_tm_req(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; em_wifi_wnm_send_bss_tm_req_suite[i].test_name != NULL; i++) {
		hwr_ewb_case_t *test = &em_wifi_wnm_send_bss_tm_req_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(slab, 0x6B, sizeof(slab));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_em_wifi_wnm_send_bss_tm_req(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_wnm_send_bss_tm_req (wifi-emulator): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

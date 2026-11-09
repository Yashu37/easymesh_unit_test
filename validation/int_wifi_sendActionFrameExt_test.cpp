/*
 * TEST RUNNER: int_wifi_sendActionFrameExt_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_sendActionFrameExt() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The function takes a MAC address array and a frame pointer it must never read: the runner POISONS the
 * whole 6-byte MAC array and (frame mode 1) the whole 256-byte frame slab, plus the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  Any read or
 * write of them aborts under ASan.  After the calls it checks the return value (RETURN_ERR), that the MAC bytes, the frame slab, the guard slab and the whole
 * log are unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_isa.h"
#include <sanitizer/asan_interface.h>

static unsigned char frame_slab[256];
static mac_address_t mac_obj;
static char log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_isa_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(mac_obj, sizeof(mac_obj));
	if (t->frame_mode == 1) fn(frame_slab, sizeof(frame_slab));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison -- returns what wifi_sendActionFrameExt returned (last call) */
static int test_int_wifi_sendActionFrameExt(const hwr_isa_case_t *t)
{
	UCHAR *frame = t->frame_mode == 0 ? NULL : t->frame_mode == 1 ? frame_slab : (UCHAR *)(unsigned long)0xdeadbeefUL;
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_int_wifi_sendActionFrameExt(t->ap_index, mac_obj, t->frequency, t->wait, frame, t->len);
	poison(0, t);
	return ret;
}

static int check(const hwr_isa_case_t *t, int ret, char *why, size_t wn)
{
	if (ret != t->expected_ret) { snprintf(why, wn, "returned %d, expected %d", ret, t->expected_ret); return 0; }
	for (size_t k = 0; k < sizeof(mac_obj); k++) if (mac_obj[k] != 0x3C) { snprintf(why, wn, "MAC byte %zu modified", k); return 0; }
	for (size_t k = 0; k < sizeof(frame_slab); k++) if (frame_slab[k] != 0xA5) { snprintf(why, wn, "frame byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "the log was modified (the function does not log)"); return 0; }
	return 1;
}

extern "C" void run_all_tests_int_wifi_sendActionFrameExt(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; int_wifi_sendActionFrameExt_suite[i].test_name != NULL; i++) {
		hwr_isa_case_t *test = &int_wifi_sendActionFrameExt_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(mac_obj, 0x3C, sizeof(mac_obj));
		memset(frame_slab, 0xA5, sizeof(frame_slab));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_int_wifi_sendActionFrameExt(test);

		if (check(test, ret, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_sendActionFrameExt (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

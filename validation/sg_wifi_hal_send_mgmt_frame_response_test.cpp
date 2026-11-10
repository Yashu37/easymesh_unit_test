/*
 * TEST RUNNER: sg_wifi_hal_send_mgmt_frame_response_test
 *
 * frame and mac are the only memory the wrapper could touch.  The runner owns two 64-byte slabs (preset to 0xA5) and POISONS ALL of both during the call (ptr_mode 1): any read or
 * write of frame / mac by the wrapper aborts under ASan.  The guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  Checks: return value (0 for OK / DENY, -1
 * for an undefined status); the OK callee ran once per call with (ap_index, frame, len) and the DENY callee never (and vice versa); an undefined status runs neither and logs
 * "Undefined status"; the slabs and the guard slab are unchanged.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wmr.h"
#include <sanitizer/asan_interface.h>

static uint8_t frame_slab[64], mac_slab[64];
static char why[240];

static void poison(int on, const hwr_wmr_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->ptr_mode == 1) { fn(frame_slab, sizeof(frame_slab)); fn(mac_slab, sizeof(mac_slab)); }
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static uint8_t *frame_of(const hwr_wmr_case_t *t) { return t->ptr_mode == 0 ? NULL : t->ptr_mode == 1 ? frame_slab : (uint8_t *)(unsigned long)0xdeadbeefUL; }
static uint8_t *mac_of(const hwr_wmr_case_t *t) { return t->ptr_mode == 0 ? NULL : t->ptr_mode == 1 ? mac_slab : (uint8_t *)(unsigned long)0xcafef00dUL; }

/* poison, call, unpoison -- returns what the function returned (last call) */
static int test_sg_wifi_hal_send_mgmt_frame_response(const hwr_wmr_case_t *t)
{
	uint8_t *frame = frame_of(t), *mac = mac_of(t);
	int ret = 0;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) ret = hwr_sg_wifi_hal_send_mgmt_frame_response(t->ap_index, t->type, t->status, t->status_code, frame, mac, t->len, t->rssi);
	poison(0, t);
	return ret;
}

static int check(const hwr_wmr_case_t *t, int ret)
{
	const hwr_wmr_world_t *w = &hwr_wmr_world;
	int ok = t->status == 0, deny = t->status == 1;
	int has = strstr(hwr_log_buf, "Undefined status") != NULL;

	if (ret != t->expected_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->expected_ret); return 0; }
	if (w->ok_calls != (ok ? t->calls : 0)) { snprintf(why, sizeof(why), "supplicant-event callee ran %d times, expected %d", w->ok_calls, ok ? t->calls : 0); return 0; }
	if (w->deny_calls != (deny ? t->calls : 0)) { snprintf(why, sizeof(why), "failure callee ran %d times, expected %d", w->deny_calls, deny ? t->calls : 0); return 0; }
	if (ok && (w->ap != t->ap_index || w->frame != frame_of(t) || w->len != t->len)) { snprintf(why, sizeof(why), "supplicant-event callee got different arguments"); return 0; }
	if (deny && (w->fap != t->ap_index || w->mac != mac_of(t) || w->type != t->type || w->status_code != t->status_code || w->rssi != t->rssi)) { snprintf(why, sizeof(why), "failure callee got different arguments"); return 0; }
	if (t->prefill < 200 && has != (!ok && !deny)) { snprintf(why, sizeof(why), "\"Undefined status\" log %s, expected %s", has ? "present" : "absent", (!ok && !deny) ? "present" : "absent"); return 0; }
	for (size_t k = 0; k < sizeof(frame_slab); k++) if (frame_slab[k] != 0xA5 || mac_slab[k] != 0xA5) { snprintf(why, sizeof(why), "frame / mac slab byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_send_mgmt_frame_response(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_send_mgmt_frame_response_suite[i].test_name != NULL; i++) {
		hwr_wmr_case_t *test = &sg_wifi_hal_send_mgmt_frame_response_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(&hwr_wmr_world, 0, sizeof(hwr_wmr_world));
		memset(frame_slab, 0xA5, sizeof(frame_slab)); memset(mac_slab, 0xA5, sizeof(mac_slab));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		int ret = test_sg_wifi_hal_send_mgmt_frame_response(test);

		if (check(test, ret)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=%d, got=%d) %s =====\n", test->test_name, test->expected_ret, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_send_mgmt_frame_response: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

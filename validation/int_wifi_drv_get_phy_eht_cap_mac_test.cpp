/*
 * TEST RUNNER: int_wifi_drv_get_phy_eht_cap_mac_test
 *
 * Same shape as the other *_test.cpp runners: test_int_wifi_drv_get_phy_eht_cap_mac() POISONS what the function must not touch, calls the handler and
 * unpoisons; run_all_tests compares the result.  The runner owns a struct eht_capabilities and a struct nlattr * array (NL80211_BAND_IFTYPE_ATTR_MAX + 1
 * entries); when the case passes them they are fully POISONED during the call (any read or write aborts under ASan).  The guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.  The function has no return value: the checks are that the struct bytes, the array and the guard slab are
 * unchanged and that the log holds one "not implemented" line per call when the line fits, or is unchanged when the slot is (almost) full.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_ihe.h"
#include <sanitizer/asan_interface.h>

static struct eht_capabilities eht_obj;
static struct nlattr *tb_arr[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
static char log_before[HWR_LOG_SZ];

static void poison(int on, const hwr_ihe_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->eht_mode == 1) fn(&eht_obj, sizeof(eht_obj));
	if (t->tb_mode == 1) fn(tb_arr, sizeof(tb_arr));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_int_wifi_drv_get_phy_eht_cap_mac(const hwr_ihe_case_t *t)
{
	struct eht_capabilities *eht = t->eht_mode == 0 ? NULL : t->eht_mode == 1 ? &eht_obj : (struct eht_capabilities *)(unsigned long)0xdeadbeefUL;
	struct nlattr **tb = t->tb_mode == 0 ? NULL : t->tb_mode == 1 ? tb_arr : (struct nlattr **)(unsigned long)0xdeadbeefUL;

	poison(1, t);
	for (int i = 0; i < t->calls; i++) hwr_int_wifi_drv_get_phy_eht_cap_mac(eht, tb);
	poison(0, t);
}

static int count_lines(const char *s)
{
	int n = 0;
	for (const char *p = s; (p = strstr(p, "not implemented\n")) != NULL; p++) n++;
	return n;
}

static int check(const hwr_ihe_case_t *t, char *why, size_t wn)
{
	static unsigned char eht_ref[sizeof(eht_obj)];

	memset(eht_ref, 0x6B, sizeof(eht_ref));
	if (memcmp(&eht_obj, eht_ref, sizeof(eht_obj)) != 0) { snprintf(why, wn, "eht_capab was modified"); return 0; }
	for (size_t k = 0; k < sizeof(tb_arr); k++) if (((unsigned char *)tb_arr)[k] != 0x6B) { snprintf(why, wn, "tb array byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, wn, "guard byte %d modified", k); return 0; }
	if (t->prefill >= HWR_LOG_USE - 1) {
		if (memcmp(hwr_log_buf, log_before, HWR_LOG_SZ) != 0) { snprintf(why, wn, "log modified although the slot is full"); return 0; }
	} else if (t->prefill + 80 * t->calls < HWR_LOG_USE - 1) {
		int n = count_lines(hwr_log_buf + t->prefill);
		if (n != t->calls) { snprintf(why, wn, "%d 'not implemented' lines logged, expected %d", n, t->calls); return 0; }
	} else {
		/* the slot has room for only part of a line: the text is truncated at HWR_LOG_USE, what was there before must stay */
		if (memcmp(hwr_log_buf, log_before, t->prefill) != 0) { snprintf(why, wn, "existing log text was modified"); return 0; }
		if (t->prefill + 80 < HWR_LOG_USE - 1 && count_lines(hwr_log_buf + t->prefill) < 1) { snprintf(why, wn, "no 'not implemented' line logged"); return 0; }
	}
	return 1;
}

extern "C" void run_all_tests_int_wifi_drv_get_phy_eht_cap_mac(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; int_wifi_drv_get_phy_eht_cap_mac_suite[i].test_name != NULL; i++) {
		hwr_ihe_case_t *test = &int_wifi_drv_get_phy_eht_cap_mac_suite[i];
		char why[160] = "";

		printf("--- Running Test: %s ---\n", test->test_name);

		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memcpy(log_before, hwr_log_buf, HWR_LOG_SZ);
		memset(&eht_obj, 0x6B, sizeof(eht_obj));
		memset(tb_arr, 0x6B, sizeof(tb_arr));
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		test_int_wifi_drv_get_phy_eht_cap_mac(test);

		if (check(test, why, sizeof(why))) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_drv_get_phy_eht_cap_mac (intel): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

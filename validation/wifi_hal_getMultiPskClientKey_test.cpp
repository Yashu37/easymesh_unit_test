/*
 * TEST RUNNER: wifi_hal_getMultiPskClientKey_test
 *
 * The runner owns the arguments, POISONS their tails, calls the function, UNPOISONS and checks the result:
 *   hwr_mac_slab : [sizeof(mac_address_t), end)               - the client MAC (6 bytes)
 *   hwr_key_slab : [sizeof(wifi_key_multi_psk_t), end)        - the output structure; preset to 0xA5
 *   hwr_log_buf  : [HWR_LOG_USE, HWR_LOG_SZ)
 * The function is NOT modified.  The expected result is RETURN_ERR with *key untouched (see the construct file).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "hwr_gmk.h"
#include <sanitizer/asan_interface.h>

#define PADB 64
static unsigned char hwr_mac_slab[sizeof(mac_address_t) + PADB];
static unsigned char hwr_key_slab[sizeof(wifi_key_multi_psk_t) + PADB];

static void poison_all(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(&hwr_mac_slab[sizeof(mac_address_t)], PADB);
	fn(&hwr_key_slab[sizeof(wifi_key_multi_psk_t)], PADB);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static char why[200];

static int run_case(const hwr_gmk_case_t *t)
{
	unsigned char *mac = t->null_mask & 1 ? NULL : hwr_mac_slab;
	wifi_key_multi_psk_t *key = t->null_mask & 2 ? NULL : (wifi_key_multi_psk_t *)hwr_key_slab;

	why[0] = 0;
	memset(hwr_mac_slab, 0, sizeof(hwr_mac_slab)); memcpy(hwr_mac_slab, t->mac, 6);
	memset(hwr_log_buf, 0, HWR_LOG_USE);

	for (int i = 0; i < t->calls; i++) {
		memset(hwr_key_slab, 0xA5, sizeof(hwr_key_slab));
		poison_all(1);
		INT ret = hwr_wifi_hal_getMultiPskClientKey(t->ap_index, mac, key);
		poison_all(0);
		if (ret != RETURN_ERR) { snprintf(why, sizeof(why), "call %d returned %d: success reported but *key was never filled", i, ret); return 0; }
		for (size_t k = 0; k < sizeof(hwr_key_slab); k++) if (hwr_key_slab[k] != 0xA5) { snprintf(why, sizeof(why), "key byte %zu modified", k); return 0; }
	}
	if (memcmp(hwr_mac_slab, t->mac, 6)) { snprintf(why, sizeof(why), "client MAC modified"); return 0; }
	if (t->check_log && (!strstr(hwr_log_buf, "wifi_hal_getMultiPskClientKey") || !strstr(hwr_log_buf, "Enter"))) { snprintf(why, sizeof(why), "log lacks function name / Enter: '%s'", hwr_log_buf); return 0; }
	return 1;
}

extern "C" void run_all_tests_wifi_hal_getMultiPskClientKey(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; wifi_hal_getMultiPskClientKey_suite[i].test_name != NULL; i++) {
		hwr_gmk_case_t *test = &wifi_hal_getMultiPskClientKey_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		int ret = run_case(test);

		if (ret == 1) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m (expected=1, got=%d) %s =====\n", test->test_name, ret, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_getMultiPskClientKey: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

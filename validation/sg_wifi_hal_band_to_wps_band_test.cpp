/*
 * TEST RUNNER: sg_wifi_hal_band_to_wps_band_test
 *
 * test_sg_wifi_hal_band_to_wps_band() POISONS what the function must not touch, calls the handler and unpoisons: the guard slab, the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) and the bytes around the output
 * (the output is an exactly sized 1-byte heap block, so a write past it is reported by ASan).  run_all_tests compares the return value and the stored byte with a reference model of the CORRECT behaviour
 * (see the construct file); on a -1 return the output must keep its sentinel.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wbw.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static int ret;
static unsigned char *out;

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_band_to_wps_band(const hwr_wbw_case_t *t)
{
	poison(1);
	ret = hwr_sg_wifi_hal_band_to_wps_band((wifi_freq_bands_t)t->band, t->out_null ? NULL : out);
	poison(0);
}

static int check(const hwr_wbw_case_t *t)
{
	if (ret != t->want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->want_ret); return 0; }
	if (!t->out_null) {
		if (t->want_ret == 0 && *out != t->want_out) { snprintf(why, sizeof(why), "stored 0x%02x, expected 0x%02x", *out, t->want_out); return 0; }
		if (t->want_ret != 0 && *out != 0xAA) { snprintf(why, sizeof(why), "output changed to 0x%02x on an error return", *out); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_band_to_wps_band(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_band_to_wps_band_suite[i].test_name != NULL; i++) {
			hwr_wbw_case_t *test = &sg_wifi_hal_band_to_wps_band_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			out = (unsigned char *)malloc(1);
			*out = 0xAA;

			test_sg_wifi_hal_band_to_wps_band(test);

			int ok = check(test);
			free(out); out = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_band_to_wps_band: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

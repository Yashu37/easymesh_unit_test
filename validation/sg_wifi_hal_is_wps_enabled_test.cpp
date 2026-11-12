/*
 * TEST RUNNER: sg_wifi_hal_is_wps_enabled_test
 *
 * test_sg_wifi_hal_is_wps_enabled() POISONS what the function must not touch, calls the handler and unpoisons: the guard slab, the log slot tail [HWR_LOG_USE, HWR_LOG_SZ), the padding around the three
 * values the function reads (all of the vap except wps.enable, all of the radio except oper_param.band, the conf padding around ignore_broadcast_ssid).  The three objects are exactly sized heap blocks, so an
 * over-read is reported by ASan.  run_all_tests compares the result with the reference model of the CORRECT behaviour (see the construct file).  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "hwr_wie.h"
#include <sanitizer/asan_interface.h>

static char why[300];
static int ret;
static hwr_wie_radio_t *radio;
static wifi_vap_info_t *vap;
static struct hwr_wie_conf *conf;

/* poison everything of [base, base+size) except [keep, keep+keep_len) */
static void poison_except(void (*fn)(void const volatile *, size_t), void *base, size_t size, size_t keep, size_t keep_len)
{
	fn(base, keep);
	fn((char *)base + keep + keep_len, size - keep - keep_len);
}

static void poison(int on)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
	poison_except(fn, vap, sizeof(*vap), (char *)&vap->u.bss_info.wps.enable - (char *)vap, sizeof(vap->u.bss_info.wps.enable));
	poison_except(fn, radio, sizeof(*radio), offsetof(hwr_wie_radio_t, oper_param) + offsetof(wifi_radio_operationParam_t, band), sizeof(radio->oper_param.band));
	fn(conf->pre, sizeof(conf->pre));
	fn(conf->post, sizeof(conf->post));
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_is_wps_enabled(const hwr_wie_case_t *t)
{
	poison(1);
	ret = hwr_sg_wifi_hal_is_wps_enabled(t->radio_null ? NULL : radio, t->vap_null ? NULL : vap, t->conf_null ? NULL : conf);
	poison(0);
}

static int check(const hwr_wie_case_t *t)
{
	if ((ret != 0) != (t->want != 0)) { snprintf(why, sizeof(why), "returned %d, expected %d", ret, t->want); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

extern "C" void run_all_tests_sg_wifi_hal_is_wps_enabled(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_is_wps_enabled_suite[i].test_name != NULL; i++) {
			hwr_wie_case_t *test = &sg_wifi_hal_is_wps_enabled_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);
			vap = (wifi_vap_info_t *)calloc(1, sizeof(*vap));
			radio = (hwr_wie_radio_t *)calloc(1, sizeof(*radio));
			conf = (struct hwr_wie_conf *)calloc(1, sizeof(*conf));
			vap->u.bss_info.wps.enable = test->enable;
			conf->ignore_broadcast_ssid = test->ignore;
			radio->oper_param.band = (wifi_freq_bands_t)test->band;

			test_sg_wifi_hal_is_wps_enabled(test);

			int ok = check(test);
			free(vap); free(radio); free(conf);
			vap = NULL; radio = NULL; conf = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_is_wps_enabled: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

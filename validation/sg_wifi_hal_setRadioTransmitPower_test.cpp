/*
 * TEST RUNNER: sg_wifi_hal_setRadioTransmitPower_test
 *
 * test_sg_wifi_hal_setRadioTransmitPower() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in radio slots other than the addressed one, the interface slot of the finder
 * that must NOT be used (the function only passes the chosen interface pointer on, it never reads it), the interfaces of the other radios, the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, which finder ran (and with which radio), whether and how
 * the driver call ran (interface pointer, txpower), guard slab unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wtp.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;

static int slot_of(const hwr_wtp_case_t *t) { return t->radioIndex < HWR_WTP_MAXR ? (int)t->radioIndex : 0; }
static int radio_ok(const hwr_wtp_case_t *t) { return !t->no_radio && t->radioIndex < HWR_WTP_MAXR; }
static int use_primary(const hwr_wtp_case_t *t) { return (t->flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) != 0; }
static int iface_there(const hwr_wtp_case_t *t) { return use_primary(t) ? t->has_primary : t->has_private; }
static int expect_ret(const hwr_wtp_case_t *t)
{
	if (!radio_ok(t) || !iface_there(t)) return -1;
	return t->drv_ret ? RETURN_ERR : RETURN_OK;
}

static void poison(int on, const hwr_wtp_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wtp_world_t *w = &hwr_wtp_world;
	int s = slot_of(t);

	for (int i = 0; i < HWR_WTP_MAXR; i++) {
		if (i != s) { fn(&w->radios[i], sizeof(w->radios[i])); fn(&w->primary[i], sizeof(w->primary[i])); fn(&w->priv[i], sizeof(w->priv[i])); }
	}
	/* the chosen interface is only passed on; the other finder's interface must stay untouched too */
	fn(use_primary(t) ? (void *)&w->priv[s] : (void *)&w->primary[s], sizeof(w->priv[s]));
	fn(&w->primary[s], sizeof(w->primary[s]));
	fn(&w->priv[s], sizeof(w->priv[s]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_setRadioTransmitPower(const hwr_wtp_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_setRadioTransmitPower((wifi_radio_index_t)t->radioIndex, t->txpower);
	poison(0, t);
}

static int check(const hwr_wtp_case_t *t)
{
	const hwr_wtp_world_t *w = &hwr_wtp_world;
	int want = expect_ret(t), s = slot_of(t);
	int p_calls = radio_ok(t) && use_primary(t), v_calls = radio_ok(t) && !use_primary(t);
	int drv = radio_ok(t) && iface_there(t);

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->primary_calls != p_calls || w->private_calls != v_calls) { snprintf(why, sizeof(why), "finders ran primary %d / private %d times, expected %d / %d", w->primary_calls, w->private_calls, p_calls, v_calls); return 0; }
	if (p_calls && w->primary_arg != &w->radios[s]) { snprintf(why, sizeof(why), "get_primary_interface got another radio"); return 0; }
	if (v_calls && w->private_arg != &w->radios[s]) { snprintf(why, sizeof(why), "get_private_vap_interface got another radio"); return 0; }
	if (w->drv_calls != (drv ? 1 : 0)) { snprintf(why, sizeof(why), "wifi_drv_set_txpower ran %d times, expected %d", w->drv_calls, drv ? 1 : 0); return 0; }
	if (drv) {
		void *want_if = use_primary(t) ? (void *)&w->primary[s] : (void *)&w->priv[s];
		if (w->drv_iface != want_if) { snprintf(why, sizeof(why), "the driver got the wrong interface"); return 0; }
		if (w->drv_txpower != t->txpower) { snprintf(why, sizeof(why), "the driver got txpower %u, expected %u", w->drv_txpower, t->txpower); return 0; }
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wtp_case_t *t)
{
	hwr_wtp_world_t *w = &hwr_wtp_world;

	memset(w, 0, sizeof(*w));
	w->hal.platform_flags = t->flags;
	w->no_radio = t->no_radio; w->has_primary = t->has_primary; w->has_private = t->has_private; w->drv_ret = t->drv_ret;
	for (int i = 0; i < HWR_WTP_MAXR; i++) { w->radios[i].index = i; w->primary[i].tag = 100 + i; w->priv[i].tag = 200 + i; }
}

extern "C" void run_all_tests_sg_wifi_hal_setRadioTransmitPower(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_setRadioTransmitPower_suite[i].test_name != NULL; i++) {
			hwr_wtp_case_t *test = &sg_wifi_hal_setRadioTransmitPower_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_setRadioTransmitPower(test);

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
	printf("\nwifi_hal_setRadioTransmitPower: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

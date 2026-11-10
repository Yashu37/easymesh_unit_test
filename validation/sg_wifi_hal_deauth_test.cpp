/*
 * TEST RUNNER: sg_wifi_hal_deauth_test
 *
 * test_sg_wifi_hal_deauth() POISONS what the function must not touch, calls the handler and unpoisons.  mac is only forwarded: the runner owns a 64-byte slab (preset to 0xA5) and
 * POISONS ALL of it during the call (mac_mode 1).  The stand-in interface slots beyond the existing ones, the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ) are poisoned too.
 * run_all_tests compares the result with a reference model of the CORRECT behaviour: for an AP VAP wifi_drv_sta_deauth runs once per call with that VAP's interface, its own_addr
 * (02:11:22:33:44:<vap>), the mac pointer and the status unchanged; for an unknown VAP or a STA VAP it does not run at all (and the function does not crash).  The slab and the guard slab
 * stay unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wda.h"
#include <sanitizer/asan_interface.h>

static uint8_t mac_slab[64];
static char why[240];

static void poison(int on, const hwr_wda_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->mac_mode == 1) fn(mac_slab, sizeof(mac_slab));
	for (unsigned i = t->n_if; i < HWR_WDA_MAXI; i++) fn(&hwr_wda_world.ifs[i], sizeof(hwr_wda_world.ifs[i]));
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

static uint8_t *mac_of(const hwr_wda_case_t *t) { return t->mac_mode == 0 ? NULL : t->mac_mode == 1 ? mac_slab : (uint8_t *)(unsigned long)0xdeadbeefUL; }

/* poison, call, unpoison */
static void test_sg_wifi_hal_deauth(const hwr_wda_case_t *t)
{
	uint8_t *mac = mac_of(t);

	poison(1, t);
	for (int i = 0; i < t->calls; i++) hwr_sg_wifi_hal_deauth(t->vap_index, t->status, mac);
	poison(0, t);
}

static int check(const hwr_wda_case_t *t)
{
	const hwr_wda_world_t *w = &hwr_wda_world;
	int exists = t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if;
	int want = (exists && !t->sta) ? t->calls : 0;
	u8 own[ETH_ALEN] = { 0x02, 0x11, 0x22, 0x33, 0x44, (u8)t->vap_index };

	if (w->deauth_calls != want) { snprintf(why, sizeof(why), "wifi_drv_sta_deauth ran %d times, expected %d", w->deauth_calls, want); return 0; }
	if (want) {
		if (w->d_if != &w->ifs[t->vap_index]) { snprintf(why, sizeof(why), "deauth got a different interface"); return 0; }
		if (memcmp(w->d_own, own, ETH_ALEN) != 0) { snprintf(why, sizeof(why), "own_addr %02x:%02x:%02x:%02x:%02x:%02x, expected the VAP's", w->d_own[0], w->d_own[1], w->d_own[2], w->d_own[3], w->d_own[4], w->d_own[5]); return 0; }
		if (w->d_mac != mac_of(t) || w->d_status != t->status) { snprintf(why, sizeof(why), "deauth got a different mac pointer / status"); return 0; }
	}
	for (size_t k = 0; k < sizeof(mac_slab); k++) if (mac_slab[k] != 0xA5) { snprintf(why, sizeof(why), "mac slab byte %zu modified", k); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wda_case_t *t)
{
	hwr_wda_world_t *w = &hwr_wda_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	w->hal.num_ifs = t->n_if;
	for (unsigned i = 0; i < HWR_WDA_MAXI; i++) {
		w->ifs[i].vap_info.vap_index = i;
		w->ifs[i].vap_info.vap_mode = wifi_vap_mode_ap;
		w->ifs[i].u.ap.hapd.own_addr[0] = 0x02; w->ifs[i].u.ap.hapd.own_addr[1] = 0x11; w->ifs[i].u.ap.hapd.own_addr[2] = 0x22;
		w->ifs[i].u.ap.hapd.own_addr[3] = 0x33; w->ifs[i].u.ap.hapd.own_addr[4] = 0x44; w->ifs[i].u.ap.hapd.own_addr[5] = (u8)i;
	}
	if (t->sta && t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if) {
		w->ifs[t->vap_index].vap_info.vap_mode = wifi_vap_mode_sta;
		memset(&w->ifs[t->vap_index].u, 0xEE, sizeof(w->ifs[t->vap_index].u));
	}
}

extern "C" void run_all_tests_sg_wifi_hal_deauth(void)
{
	int pass = 0, fail = 0;

	for (int i = 0; sg_wifi_hal_deauth_suite[i].test_name != NULL; i++) {
		hwr_wda_case_t *test = &sg_wifi_hal_deauth_suite[i];

		printf("--- Running Test: %s ---\n", test->test_name);

		setup(test);
		memset(mac_slab, 0xA5, sizeof(mac_slab));
		memset(hwr_log_buf, 0, HWR_LOG_SZ);
		memset(hwr_log_buf, 'x', test->prefill);
		memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

		test_sg_wifi_hal_deauth(test);

		if (check(test)) {
			printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
			pass++;
		} else {
			printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
			fail++;
		}
		printf("------------------------------------------------------------------------------------------------------------------------------\n");
	}
	printf("\nwifi_hal_deauth: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

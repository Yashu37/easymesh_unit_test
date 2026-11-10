/*
 * TEST RUNNER: sg_wifi_hal_kickAssociatedDevice_test
 *
 * test_sg_wifi_hal_kickAssociatedDevice() POISONS what the function must not touch, calls the handler and unpoisons: the bytes of the runner's 16-byte mac slab beyond the 6 the function may read, the union
 * of every STA VAP (the function must not read wpa_supplicant data as a hostapd station list), the interface slots beyond the existing ones, the station-list nodes beyond the list of each AP interface, the
 * guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return value, the wifi_drv_sta_disassoc
 * calls (interface, own_addr, addr, reason, in list order), the hapd lock released, the mac slab and guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <string.h>
#include "hwr_wka.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static unsigned char mac_slab[16];

static int exists(const hwr_wka_case_t *t) { return t->vap_index >= 0 && (unsigned)t->vap_index < t->n_if; }
static int is_sta(const hwr_wka_case_t *t, int k) { return (t->sta_mask >> k) & 1; }
static int calls_of(const hwr_wka_case_t *t) { return t->calls ? t->calls : 1; }

static void fill_mac(const hwr_wka_case_t *t, unsigned char *m)
{
	static const unsigned char bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, nb[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
	int k = exists(t) ? t->vap_index : 0;
	unsigned char first[6] = { 0x02, 0xAA, (unsigned char)k, 0, 0, 0 }, other[6] = { 0x02, 0xBB, 0x01, 0x02, 0x03, 0x04 }, own[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, (unsigned char)k }, zero[6] = { 0 };

	switch (t->mac_mode) {
	case 1: memcpy(m, bc, 6); break;
	case 2: memcpy(m, first, 6); break;
	case 3: memcpy(m, other, 6); break;
	case 4: memcpy(m, zero, 6); break;
	case 5: memcpy(m, nb, 6); break;
	default: memcpy(m, own, 6); break;
	}
}

static void poison(int on, const hwr_wka_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	if (t->mac_mode != 0) fn(mac_slab + 6, sizeof(mac_slab) - 6);
	for (unsigned i = t->n_if; i < HWR_WKA_MAXI; i++) fn(&hwr_wka_world.ifs[i], sizeof(hwr_wka_world.ifs[i]));
	for (unsigned i = 0; i < t->n_if; i++) {
		if (is_sta(t, i)) fn(&hwr_wka_world.ifs[i].u, sizeof(hwr_wka_world.ifs[i].u));
		else for (unsigned k = t->n_sta; k < HWR_WKA_MAXN; k++) fn(&hwr_wka_world.nodes[i][k], sizeof(hwr_wka_world.nodes[i][k]));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_kickAssociatedDevice(const hwr_wka_case_t *t)
{
	poison(1, t);
	for (int i = 0; i < calls_of(t); i++) ret_val = hwr_sg_wifi_hal_kickAssociatedDevice(t->vap_index, t->mac_mode == 0 ? NULL : mac_slab);
	poison(0, t);
}

static int check(const hwr_wka_case_t *t)
{
	const hwr_wka_world_t *w = &hwr_wka_world;
	int ok_ap = exists(t) && !is_sta(t, t->vap_index) && t->mac_mode != 0 && t->n_sta > 0;
	int want_ret = ok_ap ? 0 : -1, per = 0, k = exists(t) ? t->vap_index : 0;
	unsigned char own[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, (unsigned char)k };

	if (ok_ap) per = t->mac_mode == 1 ? (int)t->n_sta : 1;
	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	if (w->ncalls != per * calls_of(t)) { snprintf(why, sizeof(why), "wifi_drv_sta_disassoc ran %d times, expected %d", w->ncalls, per * calls_of(t)); return 0; }
	for (int c = 0; c < w->ncalls && c < HWR_WKA_MAXC; c++) {
		int j = c % per;
		unsigned char want[6];
		if (t->mac_mode == 1) { want[0] = 0x02; want[1] = 0xAA; want[2] = (unsigned char)k; want[3] = (unsigned char)j; want[4] = 0; want[5] = 0; }
		else fill_mac(t, want);
		if (w->calls[c].intf != &w->ifs[k]) { snprintf(why, sizeof(why), "disassoc %d got a different interface", c); return 0; }
		if (memcmp(w->calls[c].own, own, 6) != 0) { snprintf(why, sizeof(why), "disassoc %d own_addr is not the VAP's", c); return 0; }
		if (memcmp(w->calls[c].addr, want, 6) != 0) { snprintf(why, sizeof(why), "disassoc %d addr %02x:%02x:%02x:%02x:%02x:%02x, expected %02x:%02x:%02x:%02x:%02x:%02x", c, w->calls[c].addr[0], w->calls[c].addr[1], w->calls[c].addr[2], w->calls[c].addr[3], w->calls[c].addr[4], w->calls[c].addr[5], want[0], want[1], want[2], want[3], want[4], want[5]); return 0; }
		if (w->calls[c].reason != WLAN_REASON_UNSPECIFIED) { snprintf(why, sizeof(why), "disassoc %d reason %d", c, w->calls[c].reason); return 0; }
	}
	if (pthread_mutex_trylock(&((hwr_wka_world_t *)w)->hal.hapd_lock) != 0) { snprintf(why, sizeof(why), "hapd lock left locked"); return 0; }
	pthread_mutex_unlock(&((hwr_wka_world_t *)w)->hal.hapd_lock);
	if (t->mac_mode != 0) {
		unsigned char want[6]; fill_mac(t, want);
		if (memcmp(mac_slab, want, 6) != 0) { snprintf(why, sizeof(why), "mac slab modified"); return 0; }
		for (size_t j = 6; j < sizeof(mac_slab); j++) if (mac_slab[j] != 0xA5) { snprintf(why, sizeof(why), "mac slab byte %zu modified", j); return 0; }
	}
	for (int j = 0; j < HWR_GUARD_SZ; j++) if (hwr_guard_slab[j] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", j); return 0; }
	return 1;
}

static void setup(const hwr_wka_case_t *t)
{
	hwr_wka_world_t *w = &hwr_wka_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	w->hal.num_ifs = t->n_if;
	memset(mac_slab, 0xA5, sizeof(mac_slab));
	fill_mac(t, mac_slab);
	for (unsigned i = 0; i < HWR_WKA_MAXI; i++) {
		wifi_interface_info_t *f = &w->ifs[i];
		f->vap_info.vap_index = i;
		f->vap_info.vap_mode = (i < t->n_if && is_sta(t, i)) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		if (i < t->n_if && is_sta(t, i)) { memset(&f->u, 0xEE, sizeof(f->u)); continue; }
		unsigned char own[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, (unsigned char)i };
		memcpy(f->u.ap.hapd.own_addr, own, 6);
		for (unsigned k = 0; k < HWR_WKA_MAXN; k++) {
			struct sta_info *n = &w->nodes[i][k];
			unsigned char a[6] = { 0x02, 0xAA, (unsigned char)i, (unsigned char)k, 0, 0 };
			memcpy(n->addr, a, 6);
			n->next = (k + 1 < t->n_sta) ? &w->nodes[i][k + 1] : NULL;
		}
		f->u.ap.hapd.sta_list = t->n_sta ? &w->nodes[i][0] : NULL;
	}
}

extern "C" void run_all_tests_sg_wifi_hal_kickAssociatedDevice(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_kickAssociatedDevice_suite[i].test_name != NULL; i++) {
			hwr_wka_case_t *test = &sg_wifi_hal_kickAssociatedDevice_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_log_buf, 'x', test->prefill);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_kickAssociatedDevice(test);

			if (check(test)) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_kickAssociatedDevice: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

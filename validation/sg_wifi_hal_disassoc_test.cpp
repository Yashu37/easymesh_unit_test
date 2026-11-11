/*
 * TEST RUNNER: sg_wifi_hal_disassoc_test
 *
 * test_sg_wifi_hal_disassoc() POISONS what the function must not touch, calls the handler and unpoisons: the interfaces other than the addressed one (all of them when no interface exists for the vap index),
 * everything of the addressed interface except hapd.own_addr (vap_index and the padding before the union, hapd pad members, the union tail, trailing padding), the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The mac is an exact heap block of 6 bytes.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): no driver call for an
 * unknown vap index, otherwise one call with the right interface / own address / mac pointer / (u16)status, hapd_lock free during and after, guard slab unchanged.  Rows with last = 1 break the original: they
 * run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "hwr_wdi.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static unsigned char *mac;

static const int vaps[HWR_WDI_MAXI] = { 0, 1, 5, 14 };
static int idx_of(int vap) { for (int i = 0; i < HWR_WDI_MAXI; i++) if (vaps[i] == vap) return i; return -1; }

static void poison(int on, const hwr_wdi_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wdi_world_t *w = &hwr_wdi_world;
	int a = idx_of(t->vap_index);

	for (int i = 0; i < HWR_WDI_MAXI; i++) {
		wifi_interface_info_t *f = &w->ifs[i];
		if (i != a) { fn(f, sizeof(*f)); continue; }
		fn(&f->vap_index, sizeof(f->vap_index)); fn(f->pad1, sizeof(f->pad1));
		fn(f->u.ap.hapd.pad_before, sizeof(f->u.ap.hapd.pad_before)); fn(f->u.ap.hapd.pad_after, sizeof(f->u.ap.hapd.pad_after));
		fn((char *)&f->u.ap.hapd + sizeof(struct hostapd_data), sizeof(f->u) - sizeof(struct hostapd_data));
		fn(f->pad2, sizeof(f->pad2));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_disassoc(const hwr_wdi_case_t *t)
{
	poison(1, t);
	hwr_sg_wifi_hal_disassoc(t->vap_index, t->status, mac);
	poison(0, t);
}

static int check(const hwr_wdi_case_t *t)
{
	const hwr_wdi_world_t *w = &hwr_wdi_world;
	int a = idx_of(t->vap_index);
	pthread_mutex_t *m = (pthread_mutex_t *)&w->hal.hapd_lock;

	if (a < 0) {
		if (w->calls != 0) { snprintf(why, sizeof(why), "driver called %d times for an unknown vap index", w->calls); return 0; }
	} else {
		unsigned char own[6]; memset(own, t->own_kind == 1 ? 0xff : t->own_kind == 2 ? 0 : 0x10 + a, 6);
		if (w->calls != 1) { snprintf(why, sizeof(why), "driver called %d times, expected 1", w->calls); return 0; }
		if (w->call_priv != (void *)&w->ifs[a]) { snprintf(why, sizeof(why), "wrong interface passed to the driver"); return 0; }
		if (memcmp(w->call_own, own, 6) != 0) { snprintf(why, sizeof(why), "own address wrong"); return 0; }
		if (w->call_addr != mac) { snprintf(why, sizeof(why), "mac pointer not passed through"); return 0; }
		if (w->call_reason != (u16)t->status) { snprintf(why, sizeof(why), "reason %u, expected %u", w->call_reason, (u16)t->status); return 0; }
		if (!w->lock_free_in_call) { snprintf(why, sizeof(why), "hapd_lock held while the driver runs"); return 0; }
	}
	if (pthread_mutex_trylock(m) != 0) { snprintf(why, sizeof(why), "hapd_lock still locked"); return 0; }
	pthread_mutex_unlock(m);
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wdi_case_t *t)
{
	hwr_wdi_world_t *w = &hwr_wdi_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	for (int i = 0; i < HWR_WDI_MAXI; i++) {
		w->ifs[i].vap_index = vaps[i]; w->vap_ids[i] = vaps[i];
		memset(w->ifs[i].u.ap.hapd.own_addr, (t->own_kind == 1 && i == idx_of(t->vap_index)) ? 0xff : (t->own_kind == 2 && i == idx_of(t->vap_index)) ? 0 : 0x10 + i, 6);
	}
	mac = (unsigned char *)malloc(6);
	if (t->mac_mode == 1) { unsigned char m[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 }; memcpy(mac, m, 6); }
	else memset(mac, t->mac_mode == 2 ? 0xff : 0, 6);
}

extern "C" void run_all_tests_sg_wifi_hal_disassoc(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_disassoc_suite[i].test_name != NULL; i++) {
			hwr_wdi_case_t *test = &sg_wifi_hal_disassoc_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_disassoc(test);

			int ok = check(test);
			free(mac); mac = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_disassoc: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

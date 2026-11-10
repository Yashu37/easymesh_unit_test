/*
 * TEST RUNNER: sg_wifi_hal_delHostapdDenyAclDevice_test
 *
 * test_sg_wifi_hal_delHostapdDenyAclDevice() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots beyond the ones in the world, the hostapd union of every
 * interface other than the addressed AP one (the whole union of the addressed one when it is a STA VAP), the stand-in hostapd conf / iface structs on the paths that must stop before reaching them (no
 * interface, STA VAP, MAC NULL, conf NULL), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The MAC string is an exact heap copy.  run_all_tests compares the result with a reference model of
 * the CORRECT behaviour (see the construct file): return value, the deny list (entries and count, a listed MAC removed with the order of the others kept), the hostapd_set_acl call
 * count, hapd_lock unlocked, guard slab unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wdd.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static char *macstr;
static struct mac_acl_entry bef_list[64];
static int bef_n;

static const char *kind_str(int k)
{
	switch (k) {
	case 0: return "02:00:00:00:00:99";
	case 1: return "0A:0B:0C:0D:0E:0F";
	case 2: return "02:00:00:00:00:01";
	case 3: return "02:00:00:00";
	case 4: return "02:00:00:00:00:zz";
	case 5: return "";
	case 6: return "020000000099";
	case 7: return "02:00:00:00:00:99 VLAN_ID=5";
	case 9: return "02:00:00:00:00:02";
	case 10: return "02:00:00:00:00:03";
	default: return "02:00:00:00:00:99xyz";
	}
}
static void kind_mac(int k, unsigned char *m)
{
	static const unsigned char u[6] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	if (k == 1) { memcpy(m, u, 6); return; }
	unsigned char v[6] = { 0x02, 0, 0, 0, 0, (unsigned char)(k == 2 ? 0x01 : k == 9 ? 0x02 : k == 10 ? 0x03 : 0x99) };
	memcpy(m, v, 6);
}
static int mac_parses(int k) { return k == 0 || k == 1 || k == 2 || k == 7 || k == 8 || k == 9 || k == 10; }
static int slot_ap(const hwr_wdd_case_t *t) { return t->ap_pos; }
/* the call stops before looking at hapd->conf */
static int stops_early(const hwr_wdd_case_t *t) { return t->no_iface || t->vap_mode_sta || t->mac_null; }
/* 1-based position of the requested MAC in the initial list (0: not listed) */
static int listed_pos(const hwr_wdd_case_t *t) { int p = t->mac_kind == 2 ? 1 : t->mac_kind == 9 ? 2 : t->mac_kind == 10 ? 3 : 0; return (p && p <= t->pre_n) ? p : 0; }
/* expected result: 1 ok, 0 error */
static int expect_ok(const hwr_wdd_case_t *t)
{
	if (stops_early(t) || t->conf_null || t->iface_null) return 0;
	if (t->pre_n > 0 && !mac_parses(t->mac_kind)) return 0;
	return 1;
}
static int expect_removed(const hwr_wdd_case_t *t) { return expect_ok(t) && t->pre_n > 0 && listed_pos(t) > 0; }

static void poison(int on, const hwr_wdd_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wdd_world_t *w = &hwr_wdd_world;

	for (int k = t->n_if; k < HWR_WDD_MAXI; k++) fn(&w->ifs[k], sizeof(w->ifs[k]));
	for (int k = 0; k < t->n_if; k++) {
		if (k == slot_ap(t) && !t->vap_mode_sta) continue;
		fn(&w->ifs[k].u, sizeof(w->ifs[k].u));
	}
	if (stops_early(t) || t->conf_null) { fn(&w->hconf, sizeof(w->hconf)); fn(&w->hiface, sizeof(w->hiface)); }
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_delHostapdDenyAclDevice(const hwr_wdd_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_delHostapdDenyAclDevice(t->apIndex, t->mac_null ? NULL : macstr);
	poison(0, t);
}

static int check(const hwr_wdd_case_t *t)
{
	hwr_wdd_world_t *w = &hwr_wdd_world;
	int ok = expect_ok(t), removed = expect_removed(t);
	int want_ret = ok ? RETURN_OK : RETURN_ERR;

	if (ret_val != want_ret) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want_ret); return 0; }
	if (!stops_early(t) && !t->conf_null) {
		int wn = bef_n - (removed ? 1 : 0), pos = listed_pos(t);
		if (w->hconf.num_deny_mac != wn) { snprintf(why, sizeof(why), "deny list has %d entries, expected %d", w->hconf.num_deny_mac, wn); return 0; }
		for (int i = 0, j = 0; i < bef_n; i++) {
			if (removed && i + 1 == pos) continue;
			if (memcmp(w->hconf.deny_mac[j].addr, bef_list[i].addr, 6) != 0) { snprintf(why, sizeof(why), "deny list entry %d is not the original entry %d", j, i); return 0; }
			j++;
		}
	}
	if (w->set_acl_calls != (ok ? 1 : 0)) { snprintf(why, sizeof(why), "hostapd_set_acl ran %d times, expected %d", w->set_acl_calls, ok ? 1 : 0); return 0; }
	if (pthread_mutex_trylock(&w->hal.hapd_lock) != 0) { snprintf(why, sizeof(why), "hapd_lock left locked"); return 0; }
	pthread_mutex_unlock(&w->hal.hapd_lock);
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wdd_case_t *t)
{
	hwr_wdd_world_t *w = &hwr_wdd_world;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->hal.hapd_lock, NULL);
	w->n_if = t->n_if;
	w->hiface.drv_max_acl_mac_addrs = 5;
	if (t->pre_n) {
		w->hconf.deny_mac = (struct mac_acl_entry *)malloc(t->pre_n * sizeof(struct mac_acl_entry));
		for (int i = 0; i < t->pre_n; i++) { unsigned char m[6] = { 0x02, 0, 0, 0, 0, (unsigned char)(i + 1) }; memcpy(w->hconf.deny_mac[i].addr, m, 6); }
		w->hconf.num_deny_mac = t->pre_n;
	}
	bef_n = t->pre_n;
	if (t->pre_n) memcpy(bef_list, w->hconf.deny_mac, t->pre_n * sizeof(bef_list[0]));
	for (int k = 0; k < t->n_if; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		f->vap_info.vap_index = (k == t->ap_pos && !t->no_iface) ? (unsigned)t->apIndex : 100u + k;
		f->vap_info.vap_mode = (k == t->ap_pos && t->vap_mode_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		if (f->vap_info.vap_mode == wifi_vap_mode_ap) {
			f->u.ap.hapd.conf = (k == t->ap_pos && t->conf_null) ? NULL : &w->hconf;
			f->u.ap.hapd.iface = (k == t->ap_pos && t->iface_null) ? NULL : &w->hiface;
		} else f->u.sta.state = 1;
	}
	macstr = strdup(kind_str(t->mac_kind));
}

static void cleanup(void)
{
	free(hwr_wdd_world.hconf.deny_mac); hwr_wdd_world.hconf.deny_mac = NULL;
	free(macstr); macstr = NULL;
}

extern "C" void run_all_tests_sg_wifi_hal_delHostapdDenyAclDevice(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_delHostapdDenyAclDevice_suite[i].test_name != NULL; i++) {
			hwr_wdd_case_t *test = &sg_wifi_hal_delHostapdDenyAclDevice_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_delHostapdDenyAclDevice(test);

			int ok = check(test);
			cleanup();
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_delHostapdDenyAclDevice: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

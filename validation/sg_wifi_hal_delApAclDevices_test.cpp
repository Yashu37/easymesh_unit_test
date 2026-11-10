/*
 * TEST RUNNER: sg_wifi_hal_delApAclDevices_test
 *
 * test_sg_wifi_hal_delApAclDevices() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots beyond the ones in the world, the acl_map pointer of every interface other
 * than the addressed one (and of the addressed one when it is a STA VAP: the function must return before it), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  Entries are heap blocks and
 * their keys exact strdup copies; mac_str is a stack array, so a key compare that reads past the 18 bytes copied into it is a stack-buffer-overflow.  run_all_tests compares the result with a reference model of
 * the CORRECT behaviour (see the construct file): return value, the entries left in the map (none, or the long-key one), the remove / nl80211_set_acl call counts, guard slab unchanged.  Rows with last = 1
 * break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wdm.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static int total_entries;

static void norm_key(int i, char *k) { snprintf(k, 24, "02:aa:bb:cc:dd:%02x", i + 1); }
static int stops_early(const hwr_wdm_case_t *t) { return t->no_iface || t->vap_mode_sta || t->acl_map_null; }
static int expect_ret(const hwr_wdm_case_t *t)
{
	if (stops_early(t)) return RETURN_ERR;
	if (total_entries == 0) return RETURN_OK;
	return t->set_acl_ret;
}
/* entries that must remain: the long-key one when its key is longer than the 18 characters mac_addr_str holds */
static int expect_left(const hwr_wdm_case_t *t)
{
	if (stops_early(t)) return total_entries;
	return t->long_kind == 2 ? 1 : 0;
}
static wifi_interface_info_t *addressed(const hwr_wdm_case_t *t) { return &hwr_wdm_world.ifs[t->ap_pos]; }

static void poison(int on, const hwr_wdm_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wdm_world_t *w = &hwr_wdm_world;

	for (int k = t->n_if; k < HWR_WDM_MAXI; k++) fn(&w->ifs[k], sizeof(w->ifs[k]));
	for (int k = 0; k < t->n_if; k++) {
		if (k == t->ap_pos && !t->vap_mode_sta) continue;
		fn(&w->ifs[k].acl_map, sizeof(w->ifs[k].acl_map));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_delApAclDevices(const hwr_wdm_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_delApAclDevices(t->apIndex);
	poison(0, t);
}

static int check(const hwr_wdm_case_t *t)
{
	hwr_wdm_world_t *w = &hwr_wdm_world;
	int want = expect_ret(t);

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->set_acl_calls != ((!stops_early(t) && total_entries > 0) ? 1 : 0)) { snprintf(why, sizeof(why), "nl80211_set_acl ran %d times", w->set_acl_calls); return 0; }
	if (!stops_early(t)) {
		hash_map_t *mp = addressed(t)->acl_map;
		if (w->remove_calls != total_entries) { snprintf(why, sizeof(why), "hash_map_remove ran %d times, expected %d (one per entry)", w->remove_calls, total_entries); return 0; }
		if (mp->n != expect_left(t)) { snprintf(why, sizeof(why), "%d entries left in the map, expected %d", mp->n, expect_left(t)); return 0; }
	} else if (w->remove_calls != 0) { snprintf(why, sizeof(why), "hash_map_remove ran on an error path"); return 0; }
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void put_entry(hash_map_t *m, const char *key, const char *mac_str18)
{
	acl_map_t *e = (acl_map_t *)calloc(1, sizeof(acl_map_t));
	memcpy(e->mac_addr_str, mac_str18, sizeof(e->mac_addr_str));      /* exactly the 18 bytes: no terminator for a key of 18+ characters */
	m->keys[m->n] = strdup(key); m->data[m->n++] = e;
}

static void setup(const hwr_wdm_case_t *t)
{
	hwr_wdm_world_t *w = &hwr_wdm_world;
	char buf[40], lk[40];

	memset(w, 0, sizeof(*w));
	w->n_if = t->n_if; w->set_acl_ret = t->set_acl_ret;
	for (int k = 0; k < t->n_if; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		f->vap_info.vap_index = (k == t->ap_pos && !t->no_iface) ? (unsigned)t->apIndex : 100u + k;
		f->vap_info.vap_mode = (k == t->ap_pos && t->vap_mode_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		snprintf(f->name, sizeof(f->name), "wl%d", k);
		f->acl_map = &w->maps[k];
		if (k == t->ap_pos) {
			if (t->acl_map_null) f->acl_map = NULL;
			else {
				if (t->long_kind == 1) { strcpy(lk, "02:11:22:33:44:55X"); put_entry(&w->maps[k], lk, lk); }
				if (t->long_kind == 2) { strcpy(lk, "02:11:22:33:44:55 VLAN_ID=5"); put_entry(&w->maps[k], lk, lk); }
				for (int i = 0; i < t->n_entries; i++) { norm_key(i, buf); put_entry(&w->maps[k], buf, buf); }
			}
		}
	}
	total_entries = t->acl_map_null ? 0 : t->n_entries + (t->long_kind ? 1 : 0);
	if (stops_early(t) && !t->acl_map_null) total_entries = t->n_entries;
}

static void cleanup(void)
{
	hwr_wdm_world_t *w = &hwr_wdm_world;
	for (int k = 0; k < HWR_WDM_MAXI; k++) for (int i = 0; i < w->maps[k].n; i++) { free(w->maps[k].keys[i]); free(w->maps[k].data[i]); }
}

extern "C" void run_all_tests_sg_wifi_hal_delApAclDevices(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_delApAclDevices_suite[i].test_name != NULL; i++) {
			hwr_wdm_case_t *test = &sg_wifi_hal_delApAclDevices_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_delApAclDevices(test);

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
	printf("\nwifi_hal_delApAclDevices: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

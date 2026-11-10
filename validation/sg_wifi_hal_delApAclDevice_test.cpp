/*
 * TEST RUNNER: sg_wifi_hal_delApAclDevice_test
 *
 * test_sg_wifi_hal_delApAclDevice() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots beyond the ones in the world, the acl_map pointer of every interface other
 * than the addressed one (and of the addressed one when it is a STA VAP: the function must return before it), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The MAC string is an exact heap
 * copy (strlen + 1 bytes), so reading it past its terminator is a heap-buffer-overflow.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return
 * value, the ACL map (entries and order; the entry removed, or put back when nl80211_set_acl fails, with key / mac_addr_str / MAC bytes), the nl80211_set_acl call count, guard slab unchanged.  Rows with last = 1
 * break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wdl.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static char *macstr;
static char bef_key[32][24];
static int bef_n;

static void pre_mac(int i, unsigned char *m) { unsigned char v[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, (unsigned char)(i + 1) }; memcpy(m, v, 6); }
static void pre_key(int i, char *k) { unsigned char m[6]; pre_mac(i, m); snprintf(k, 24, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); }
static const char *kind_str(int kind, char *buf)
{
	switch (kind) {
	case 0: pre_key(0, buf); return buf;
	case 1: pre_key(1, buf); return buf;
	case 2: pre_key(2, buf); return buf;
	case 3: strcpy(buf, "02:00:00:00:00:99"); return buf;
	case 4: pre_key(0, buf); for (char *p = buf; *p; p++) if (*p >= 'a' && *p <= 'f') *p -= 32; return buf;
	case 5: case 6: strcpy(buf, "ab:cd"); return buf;
	default: buf[0] = 0; return buf;
	}
}
static int stops_early(const hwr_wdl_case_t *t) { return t->no_iface || t->vap_mode_sta || t->mac_null; }
static int expect_ok_ret(const hwr_wdl_case_t *t) { return !stops_early(t); }
/* index (0-based) in the initial map of the entry to remove, -1 when the MAC is not a key of the map */
static int target(const hwr_wdl_case_t *t)
{
	if (stops_early(t) || t->acl_map_null) return -1;
	if (t->mac_kind >= 0 && t->mac_kind <= 2) return t->mac_kind < t->pre_n ? t->mac_kind : -1;
	if (t->mac_kind == 5) return t->pre_n;                 /* the extra short-key entry at the end */
	return -1;
}
static int expect_ret(const hwr_wdl_case_t *t)
{
	if (!expect_ok_ret(t)) return RETURN_ERR;
	if (target(t) >= 0 && t->set_acl_ret != 0) return -1;
	return RETURN_OK;
}
static wifi_interface_info_t *addressed(const hwr_wdl_case_t *t) { return &hwr_wdl_world.ifs[t->ap_pos]; }

static void poison(int on, const hwr_wdl_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wdl_world_t *w = &hwr_wdl_world;

	for (int k = t->n_if; k < HWR_WDL_MAXI; k++) fn(&w->ifs[k], sizeof(w->ifs[k]));
	for (int k = 0; k < t->n_if; k++) {
		if (k == t->ap_pos && !t->vap_mode_sta) continue;
		fn(&w->ifs[k].acl_map, sizeof(w->ifs[k].acl_map));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_delApAclDevice(const hwr_wdl_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_delApAclDevice(t->apIndex, t->mac_null ? NULL : macstr);
	poison(0, t);
}

static int check(const hwr_wdl_case_t *t)
{
	hwr_wdl_world_t *w = &hwr_wdl_world;
	int tg = target(t), want = expect_ret(t);

	if (ret_val != want) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, want); return 0; }
	if (w->set_acl_calls != (tg >= 0 ? 1 : 0)) { snprintf(why, sizeof(why), "nl80211_set_acl ran %d times, expected %d", w->set_acl_calls, tg >= 0 ? 1 : 0); return 0; }
	if (!stops_early(t) && !t->acl_map_null) {
		hash_map_t *mp = addressed(t)->acl_map;
		int restored = tg >= 0 && t->set_acl_ret != 0 && !t->malloc_fail;      /* with malloc failing the entry cannot be put back: it stays removed, the result is -1 */
		int wn = bef_n - ((tg >= 0 && !restored) ? 1 : 0);
		if (mp->n != wn) { snprintf(why, sizeof(why), "ACL map has %d entries, expected %d", mp->n, wn); return 0; }
		if (!restored) {
			for (int i = 0, j = 0; i < bef_n; i++) {
				if (i == tg) continue;
				if (strcmp(mp->keys[j], bef_key[i]) != 0) { snprintf(why, sizeof(why), "map entry %d is \"%s\", expected \"%s\"", j, mp->keys[j], bef_key[i]); return 0; }
				j++;
			}
		} else {
			/* the entry must be back (at the end of the map) with its key, mac_addr_str and MAC bytes */
			acl_map_t *e = (acl_map_t *)mp->data[mp->n - 1];
			unsigned char m[6];
			if (strcmp(mp->keys[mp->n - 1], bef_key[tg]) != 0 || strncmp(e->mac_addr_str, bef_key[tg], sizeof(e->mac_addr_str)) != 0) { snprintf(why, sizeof(why), "the entry was not put back with its key"); return 0; }
			if (t->mac_kind != 5) { pre_mac(tg, m); if (memcmp(e->mac_addr, m, 6) != 0) { snprintf(why, sizeof(why), "the restored entry has the wrong MAC bytes"); return 0; } }
		}
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void put_entry(hash_map_t *m, const char *key, const unsigned char *mac)
{
	acl_map_t *e = (acl_map_t *)calloc(1, sizeof(acl_map_t));
	snprintf(e->mac_addr_str, sizeof(e->mac_addr_str), "%s", key);
	if (mac) memcpy(e->mac_addr, mac, 6);
	m->keys[m->n] = strdup(key); m->data[m->n++] = e;
}

static void setup(const hwr_wdl_case_t *t)
{
	hwr_wdl_world_t *w = &hwr_wdl_world;
	char buf[32];

	memset(w, 0, sizeof(*w));
	w->n_if = t->n_if; w->malloc_fail = t->malloc_fail; w->set_acl_ret = t->set_acl_ret;
	for (int k = 0; k < t->n_if; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		f->vap_info.vap_index = (k == t->ap_pos && !t->no_iface) ? (unsigned)t->apIndex : 100u + k;
		f->vap_info.vap_mode = (k == t->ap_pos && t->vap_mode_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		snprintf(f->name, sizeof(f->name), "wl%d", k);
		f->acl_map = &w->maps[k];
		if (k == t->ap_pos) {
			if (t->acl_map_null) f->acl_map = NULL;
			else {
				for (int i = 0; i < t->pre_n; i++) { unsigned char m[6]; pre_mac(i, m); pre_key(i, buf); put_entry(&w->maps[k], buf, m); }
				if (t->mac_kind == 5) put_entry(&w->maps[k], "ab:cd", NULL);
			}
		}
	}
	bef_n = 0;
	if (!t->acl_map_null) {
		for (int i = 0; i < t->pre_n; i++) pre_key(i, bef_key[bef_n++]);
		if (t->mac_kind == 5) strcpy(bef_key[bef_n++], "ab:cd");
	}
	{ const char *s = kind_str(t->mac_kind, buf); macstr = (char *)malloc(strlen(s) + 1); strcpy(macstr, s); }
}

static void cleanup(void)
{
	hwr_wdl_world_t *w = &hwr_wdl_world;
	for (int k = 0; k < HWR_WDL_MAXI; k++) for (int i = 0; i < w->maps[k].n; i++) { free(w->maps[k].keys[i]); free(w->maps[k].data[i]); }
	free(macstr); macstr = NULL;
}

extern "C" void run_all_tests_sg_wifi_hal_delApAclDevice(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_delApAclDevice_suite[i].test_name != NULL; i++) {
			hwr_wdl_case_t *test = &sg_wifi_hal_delApAclDevice_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_delApAclDevice(test);

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
	printf("\nwifi_hal_delApAclDevice: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

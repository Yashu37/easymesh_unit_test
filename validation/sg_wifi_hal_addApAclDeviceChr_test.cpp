/*
 * TEST RUNNER: sg_wifi_hal_addApAclDeviceChr_test
 *
 * test_sg_wifi_hal_addApAclDeviceChr() POISONS what the function must not touch, calls the handler and unpoisons: the interface slots beyond the ones in the world, the acl_map pointer of every interface other
 * than the addressed one (and of the addressed one when it is a STA VAP: the function must return before it), the guard slab and the log slot tail [HWR_LOG_USE, HWR_LOG_SZ).  The MAC string is an exact heap
 * copy (strlen + 1 bytes), so reading it past its terminator is a heap-buffer-overflow.  run_all_tests compares the result with a reference model of the CORRECT behaviour (see the construct file): return
 * value, the ACL map (entry added once with its key, mac_addr_str and parsed MAC bytes, or untouched), the nl80211_set_acl / nl80211_kick_device call counts, the map created when it was NULL, guard slab
 * unchanged.  Rows with last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wab.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static char *macstr;
static int bef_n;

static void pre_mac(int i, unsigned char *m) { unsigned char v[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, (unsigned char)(i + 1) }; memcpy(m, v, 6); }
static void pre_key(int i, char *k) { unsigned char m[6]; pre_mac(i, m); snprintf(k, 24, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); }
static const char *kind_str(int kind, char *buf)
{
	switch (kind) {
	case 0: return "02:11:22:33:44:55";
	case 1: return "0A:0B:0C:0D:0E:0F";
	case 2: pre_key(0, buf); return buf;
	case 3: return "ab:cd";
	case 4: return "";
	default: return "02:11:22:33:44:55 VLAN_ID=5";
	}
}
/* MAC bytes the string holds (kinds 3 and 4 have none: not checked) */
static int kind_mac(int kind, unsigned char *m)
{
	static const unsigned char a[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }, b[6] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	if (kind == 0 || kind == 5) { memcpy(m, a, 6); return 1; }
	if (kind == 1) { memcpy(m, b, 6); return 1; }
	return 0;
}
static int stops_early(const hwr_wab_case_t *t) { return t->no_iface || t->mac_null || t->vap_mode_sta; }
static int present(const hwr_wab_case_t *t) { return t->mac_kind == 2 && t->pre_n >= 1; }
static int expect_ok(const hwr_wab_case_t *t)
{
	if (stops_early(t)) return 0;
	if (t->acl_map_null && t->create_fail) return 0;
	if (present(t)) return 1;
	if (t->malloc_fail) return 0;
	return t->set_acl_ret == 0;
}
static int expect_added(const hwr_wab_case_t *t) { return !stops_early(t) && !(t->acl_map_null && t->create_fail) && !present(t) && !t->malloc_fail; }
static int expect_kick(const hwr_wab_case_t *t) { return expect_added(t) && t->set_acl_ret == 0 && t->filter_enable && t->filter_mode == 0; }
static wifi_interface_info_t *addressed(const hwr_wab_case_t *t) { return &hwr_wab_world.ifs[t->ap_pos]; }

static void poison(int on, const hwr_wab_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;
	hwr_wab_world_t *w = &hwr_wab_world;

	for (int k = t->n_if; k < HWR_WAB_MAXI; k++) fn(&w->ifs[k], sizeof(w->ifs[k]));
	for (int k = 0; k < t->n_if; k++) {
		if (k == t->ap_pos && !t->vap_mode_sta) continue;
		fn(&w->ifs[k].acl_map, sizeof(w->ifs[k].acl_map));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_addApAclDeviceChr(const hwr_wab_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_addApAclDevice_chr(t->apIndex, t->mac_null ? NULL : macstr);
	poison(0, t);
}

static int check(const hwr_wab_case_t *t)
{
	hwr_wab_world_t *w = &hwr_wab_world;
	int ok = expect_ok(t), added = expect_added(t), kick = expect_kick(t);
	unsigned char m[6];

	if (ret_val != (ok ? RETURN_OK : RETURN_ERR)) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, ok ? RETURN_OK : RETURN_ERR); return 0; }
	if (w->put_calls != (added ? 1 : 0)) { snprintf(why, sizeof(why), "hash_map_put ran %d times, expected %d", w->put_calls, added ? 1 : 0); return 0; }
	if (w->set_acl_calls != (added ? 1 : 0)) { snprintf(why, sizeof(why), "nl80211_set_acl ran %d times, expected %d", w->set_acl_calls, added ? 1 : 0); return 0; }
	if (w->kick_calls != (kick ? 1 : 0)) { snprintf(why, sizeof(why), "nl80211_kick_device ran %d times, expected %d", w->kick_calls, kick ? 1 : 0); return 0; }
	if (!stops_early(t)) {
		hash_map_t *mp = addressed(t)->acl_map;
		if (mp == NULL && !(t->acl_map_null && t->create_fail)) { snprintf(why, sizeof(why), "acl_map still NULL"); return 0; }
		if (mp) {
			if (mp->n != bef_n + (added ? 1 : 0)) { snprintf(why, sizeof(why), "ACL map has %d entries, expected %d", mp->n, bef_n + (added ? 1 : 0)); return 0; }
			if (added) {
				char tmp[32]; const char *s = kind_str(t->mac_kind, tmp); size_t n = strlen(s) < 17 ? strlen(s) : 17;
				acl_map_t *e = (acl_map_t *)mp->data[mp->n - 1];
				if (strcmp(mp->keys[mp->n - 1], s) != 0) { snprintf(why, sizeof(why), "the new key is \"%s\", expected \"%s\"", mp->keys[mp->n - 1], s); return 0; }
				if (strncmp(e->mac_addr_str, s, n) != 0 || (n < 17 && e->mac_addr_str[n] != 0)) { snprintf(why, sizeof(why), "mac_addr_str does not hold the requested string"); return 0; }
				if (kind_mac(t->mac_kind, m) && memcmp(e->mac_addr, m, 6) != 0) { snprintf(why, sizeof(why), "the new entry has the wrong MAC bytes"); return 0; }
			}
		}
	}
	for (int g = 0; g < HWR_GUARD_SZ; g++) if (hwr_guard_slab[g] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", g); return 0; }
	return 1;
}

static void setup(const hwr_wab_case_t *t)
{
	hwr_wab_world_t *w = &hwr_wab_world;
	char buf[32];

	memset(w, 0, sizeof(*w));
	w->n_if = t->n_if; w->malloc_fail = t->malloc_fail; w->create_fail = t->create_fail;
	w->set_acl_ret = t->set_acl_ret; w->kick_ret = t->kick_ret;
	for (int k = 0; k < t->n_if; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		f->vap_info.vap_index = (k == t->ap_pos && !t->no_iface) ? (unsigned)t->apIndex : 100u + k;
		f->vap_info.vap_mode = (k == t->ap_pos && t->vap_mode_sta) ? wifi_vap_mode_sta : wifi_vap_mode_ap;
		snprintf(f->name, sizeof(f->name), "wl%d", k);
		f->acl_map = &w->maps[k];
		if (k == t->ap_pos) {
			f->vap_info.u.bss_info.mac_filter_enable = t->filter_enable;
			f->vap_info.u.bss_info.mac_filter_mode = t->filter_mode ? wifi_mac_filter_mode_white_list : wifi_mac_filter_mode_black_list;
			if (t->acl_map_null) f->acl_map = NULL;
			else for (int i = 0; i < t->pre_n; i++) {
				acl_map_t *e = (acl_map_t *)calloc(1, sizeof(acl_map_t));
				pre_mac(i, e->mac_addr); pre_key(i, buf);
				snprintf(e->mac_addr_str, sizeof(e->mac_addr_str), "%s", buf);
				w->maps[k].keys[w->maps[k].n] = strdup(buf); w->maps[k].data[w->maps[k].n++] = e;
			}
		}
	}
	bef_n = t->acl_map_null ? 0 : t->pre_n;
	{ const char *s = kind_str(t->mac_kind, buf); macstr = (char *)malloc(strlen(s) + 1); strcpy(macstr, s); }
}

static void free_map(hash_map_t *m) { for (int i = 0; i < m->n; i++) { free(m->keys[i]); free(m->data[i]); } m->n = 0; }
static void cleanup(void)
{
	hwr_wab_world_t *w = &hwr_wab_world;
	for (int k = 0; k < HWR_WAB_MAXI; k++) free_map(&w->maps[k]);
	free_map(&w->created);
	free(macstr); macstr = NULL;
}

extern "C" void run_all_tests_sg_wifi_hal_addApAclDeviceChr(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_addApAclDeviceChr_suite[i].test_name != NULL; i++) {
			hwr_wab_case_t *test = &sg_wifi_hal_addApAclDeviceChr_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_addApAclDeviceChr(test);

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
	printf("\nwifi_hal_addApAclDevice (CHAR * variant): %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

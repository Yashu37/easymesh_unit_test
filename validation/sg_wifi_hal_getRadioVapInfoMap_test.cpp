/*
 * TEST RUNNER: sg_wifi_hal_getRadioVapInfoMap_test
 *
 * test_sg_wifi_hal_getRadioVapInfoMap() POISONS what the function must not touch, calls the handler and unpoisons: the stand-in radio slots other than the addressed one, the interface slots beyond the ones in
 * the radio's interface map, the map entries beyond the ones the function should write (the whole map, num_vaps included, when the call must fail without touching it), the guard slab and the log slot tail
 * [HWR_LOG_USE, HWR_LOG_SZ).  The map is a heap block of exactly sizeof(wifi_vap_info_map_t), so a write to vap_array[8..] is a heap-buffer-overflow.  run_all_tests compares the result with a reference model of
 * the CORRECT behaviour (see the construct file): return value, num_vaps, the copied vap infos with the interface MAC stored by the vap_name rule, the map untouched on failure, guard slab unchanged.  Rows with
 * last = 1 break the original: they run LAST.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hwr_wvm.h"
#include <sanitizer/asan_interface.h>

static char why[240];
static int ret_val;
static wifi_vap_info_map_t *map;
static unsigned char bef[sizeof(wifi_vap_info_map_t)];

static int slot_of(const hwr_wvm_case_t *t) { return (t->index >= 0 && t->index < HWR_WVM_MAXR) ? t->index : 0; }
static int arg_ok(const hwr_wvm_case_t *t) { return !t->null_map && t->index >= 0 && t->index < MAX_NUM_RADIOS; }
static int ok_env(const hwr_wvm_case_t *t) { return arg_ok(t) && !t->no_radio && !t->null_imap && t->n_if > 0; }
static int valid_if(const hwr_wvm_case_t *t, unsigned k) { return !((t->neg_mask >> k) & 1); }
static int expected_count(const hwr_wvm_case_t *t)
{
	int c = 0;
	if (!ok_env(t)) return 0;
	for (unsigned k = 0; k < t->n_if; k++) if (valid_if(t, k)) c++;
	return c < HWR_WVM_MAPSZ ? c : HWR_WVM_MAPSZ;
}

static void poison(int on, const hwr_wvm_case_t *t)
{
	void (*fn)(void const volatile *, size_t) = on ? __asan_poison_memory_region : __asan_unpoison_memory_region;

	for (int i = 0; i < HWR_WVM_MAXR; i++) if (i != slot_of(t)) fn(&hwr_wvm_world.radios[i], sizeof(hwr_wvm_world.radios[i]));
	for (unsigned k = t->n_if; k < HWR_WVM_MAXI; k++) fn(&hwr_wvm_world.ifs[k], sizeof(hwr_wvm_world.ifs[k]));
	if (map) {
		if (!ok_env(t)) fn(map, sizeof(*map));
		else for (int k = expected_count(t); k < HWR_WVM_MAPSZ; k++) fn(&map->vap_array[k], sizeof(map->vap_array[k]));
	}
	fn(hwr_guard_slab, HWR_GUARD_SZ);
	fn(&hwr_log_buf[HWR_LOG_USE], HWR_LOG_SZ - HWR_LOG_USE);
}

/* poison, call, unpoison */
static void test_sg_wifi_hal_getRadioVapInfoMap(const hwr_wvm_case_t *t)
{
	poison(1, t);
	ret_val = hwr_sg_wifi_hal_getRadioVapInfoMap((wifi_radio_index_t)t->index, map);
	poison(0, t);
}

static void make_name(const hwr_wvm_case_t *t, unsigned k, char *n, size_t sz)
{
	int kind = t->name_kind == 7 ? (int)(k % 3) : t->name_kind;

	memset(n, 0, sz);
	switch (kind) {
	case 0: snprintf(n, sz, "wl_ap%u", k); break;
	case 1: snprintf(n, sz, "sim_sta%u", k); break;
	case 2: snprintf(n, sz, "mesh_sta%u", k); break;
	case 3: snprintf(n, sz, "mesh_st"); break;
	case 4: break;
	case 5: memset(n, 'A' + (k % 20), sz); break;        /* fills the whole array, no terminator */
	default: snprintf(n, sz, "sim_stax"); break;
	}
}

static int starts(const char *n, size_t sz, const char *p) { size_t l = strlen(p); return l <= sz && strncmp(n, p, l) == 0; }

static int check(const hwr_wvm_case_t *t)
{
	if (!arg_ok(t)) { if (ret_val != WIFI_HAL_INVALID_ARGUMENTS) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, WIFI_HAL_INVALID_ARGUMENTS); return 0; } }
	else if (!ok_env(t)) { if (ret_val != RETURN_ERR) { snprintf(why, sizeof(why), "returned %d, expected %d", ret_val, RETURN_ERR); return 0; } }
	else {
		int cnt = expected_count(t), j = 0;
		if (ret_val != RETURN_OK) { snprintf(why, sizeof(why), "returned %d, expected 0", ret_val); return 0; }
		if (map->num_vaps != (unsigned)cnt) { snprintf(why, sizeof(why), "num_vaps %u, expected %d", map->num_vaps, cnt); return 0; }
		for (unsigned k = 0; k < t->n_if && j < cnt; k++) {
			if (!valid_if(t, k)) continue;
			wifi_vap_info_t exp = hwr_wvm_world.ifs[k].vap_info;
			const unsigned char *mac = hwr_wvm_world.ifs[k].mac;
			if (starts((char *)exp.vap_name, sizeof(exp.vap_name), "sim_sta")) memcpy(exp.u.sta_info.mac, mac, 6);
			else if (!starts((char *)exp.vap_name, sizeof(exp.vap_name), "mesh_sta")) memcpy(exp.u.bss_info.bssid, mac, 6);
			else memcpy(exp.u.sta_info.mac, mac, 6);
			if (memcmp(&map->vap_array[j], &exp, sizeof(exp)) != 0) { snprintf(why, sizeof(why), "vap_array[%d] is not interface %u (with its MAC stored by the name rule)", j, k); return 0; }
			j++;
		}
	}
	if (map && !ok_env(t) && memcmp(map, bef, sizeof(bef)) != 0) { snprintf(why, sizeof(why), "the map was modified although the call failed"); return 0; }
	for (int k = 0; k < HWR_GUARD_SZ; k++) if (hwr_guard_slab[k] != 0xA5) { snprintf(why, sizeof(why), "guard byte %d modified", k); return 0; }
	return 1;
}

static void setup(const hwr_wvm_case_t *t)
{
	hwr_wvm_world_t *w = &hwr_wvm_world;
	int slot = slot_of(t);

	memset(w, 0, sizeof(*w));
	w->no_radio = t->no_radio;
	for (int i = 0; i < HWR_WVM_MAXR; i++) { w->radios[i].index = i; w->radios[i].interface_map = &w->maps[i]; }
	if (t->null_imap) w->radios[slot].interface_map = NULL;
	for (unsigned k = 0; k < HWR_WVM_MAXI; k++) {
		wifi_interface_info_t *f = &w->ifs[k];
		unsigned char mac[6] = { 0x02, 0, 0, 0, 0, (unsigned char)(k + 1) };
		memcpy(f->mac, mac, 6);
		memset(&f->vap_info, (int)(0x30 + k), sizeof(f->vap_info));           /* distinctive contents */
		f->vap_info.vap_index = valid_if(t, k) ? t->vap_index0 + k : 0xFFFFFFFFu;
		f->vap_info.radio_index = slot;
		make_name(t, k, (char *)f->vap_info.vap_name, sizeof(f->vap_info.vap_name));
		if (k < t->n_if) w->maps[slot].items[w->maps[slot].n++] = f;
	}
	map = t->null_map ? NULL : (wifi_vap_info_map_t *)calloc(1, sizeof(wifi_vap_info_map_t));
	if (map) { memset(map, 0x5A, sizeof(*map)); map->num_vaps = 0xAAAA; memcpy(bef, map, sizeof(bef)); }
}

extern "C" void run_all_tests_sg_wifi_hal_getRadioVapInfoMap(void)
{
	int pass = 0, fail = 0;

	for (int last = 0; last < 2; last++)
		for (int i = 0; sg_wifi_hal_getRadioVapInfoMap_suite[i].test_name != NULL; i++) {
			hwr_wvm_case_t *test = &sg_wifi_hal_getRadioVapInfoMap_suite[i];

			if (test->last != last) continue;
			printf("--- Running Test: %s ---\n", test->test_name);

			setup(test);
			memset(hwr_log_buf, 0, HWR_LOG_SZ);
			memset(hwr_guard_slab, 0xA5, HWR_GUARD_SZ);

			test_sg_wifi_hal_getRadioVapInfoMap(test);

			int ok = check(test);
			free(map); map = NULL;
			if (ok) {
				printf("================== %s: \033[32mPASS\033[0m ==============\n", test->test_name);
				pass++;
			} else {
				printf("===== %s: \033[31mFAIL\033[0m %s =====\n", test->test_name, why);
				fail++;
			}
			printf("------------------------------------------------------------------------------------------------------------------------------\n");
		}
	printf("\nwifi_hal_getRadioVapInfoMap: %d cases, %d passed, %d failed\n", pass + fail, pass, fail);
}

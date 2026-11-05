/*
 * UNIT TEST (input constructor): construct_wifi_hal_steering_clientRemove
 *
 * wifi_hal_steering_clientRemove(steeringgroupIndex, apIndex, client_mac) looks the AP up (unknown ->
 * RETURN_ERR), formats the MAC, and under steering_data_lock finds the client's entry in
 * interface->bm_sta_map; if found it calls wifi_steering_del_mac_list(apIndex, entry) and then
 * steering_del_stalist(interface, entry->mac_addr, BM_STA_TYPE_CLIENT_SET) (which clears that type bit and
 * frees the entry when no other type is left).  It then returns nl80211_kick_device(interface, client_mac).
 *
 * Stubs (below): the AP lookup knows apIndex 0..3; hash_map_get walks a 4-slot table; steering_del_stalist is a
 * faithful model of the real function (type bit cleared, entry removed and POISONED as "freed" when no type
 * is left) so a later use of the entry is an ASan error; nl80211_kick_device reads the 6 MAC bytes like the real
 * nla_put and returns a configurable result.
 * Inputs crossed: AP 0..3 with the entry present (type CLIENT_SET only: removed; CLIENT_SET|assoc: kept with the
 * bit cleared), no entry (only the kick), unknown APs (4, -1, INT_MAX, INT_MIN), bm_sta_map NULL, another
 * client's entry left alone, kick failing, wifi_steering_del_mac_list failing, groups 0, 7, 8, 255, UINT_MAX
 * (the group is not used: design note), MAC variants, repeated calls, the log line, and a NULL client_mac
 * (crashes the unfixed function: forked rows; with an unknown AP the AP lookup returns first: plain row).
 * A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_grm.h"
#include <sanitizer/asan_interface.h>

hwr_grm_rec_t hwr_grm_rec;
static hwr_grm_if_t g_ifs[4] = { { 0, NULL }, { 1, NULL }, { 2, NULL }, { 3, NULL } };
static hwr_grm_map_t g_maps[4];
static int g_kick_ret, g_del_ret;

hwr_grm_map_t *hwr_grm_map(int ap) { return &g_maps[ap]; }
static void put(hwr_grm_map_t *m, const unsigned char *mac, hwr_bm_sta_list_t *e)
{
	snprintf(m->key[m->n], 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	m->data[m->n++] = e;
}
void hwr_grm_configure(int ap, int map_null, hwr_bm_sta_list_t *sta, const unsigned char *mac, hwr_bm_sta_list_t *other, int kick_ret, int del_ret)
{
	static const unsigned char omac[6] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	memset(&hwr_grm_rec, 0, sizeof(hwr_grm_rec)); memset(g_maps, 0, sizeof(g_maps));
	for (int i = 0; i < 4; i++) g_ifs[i].bm_sta_map = &g_maps[i];
	if (ap >= 0 && ap < 4 && map_null) g_ifs[ap].bm_sta_map = NULL;
	if (ap >= 0 && ap < 4 && sta) put(&g_maps[ap], mac, sta);
	if (ap >= 0 && ap < 4 && other) put(&g_maps[ap], omac, other);
	g_kick_ret = kick_ret; g_del_ret = del_ret;
}

extern "C" hwr_grm_if_t *hwr_grm_get_interface(unsigned int vap_index) { return vap_index < 4 ? &g_ifs[vap_index] : NULL; }
extern "C" void *hwr_grm_hash_map_get(hwr_grm_map_t *map, const char *key)
{
	if (map == NULL) return NULL;
	for (int i = 0; i < map->n; i++) if (map->data[i] && !strncmp(map->key[i], key, 18)) return map->data[i];
	return NULL;
}
extern "C" int hwr_grm_del_mac_list(uint32_t vap_index, hwr_bm_sta_list_t *sta_info)
{
	hwr_grm_rec.del_calls++; hwr_grm_rec.del_seq = ++hwr_grm_rec.seq; hwr_grm_rec.del_vap = vap_index; hwr_grm_rec.del_sta = sta_info;
	memcpy(hwr_grm_rec.del_mac, sta_info->mac_addr, 6);          /* reads the entry (a freed entry is poisoned) */
	return g_del_ret;
}
/* model of steering_del_stalist (src/wifi_hal_nl80211.c:1093) */
extern "C" void hwr_grm_del_stalist(hwr_grm_if_t *interface, mac_address_t client_mac, uint8_t type)
{
	char key[18];
	hwr_grm_rec.sl_calls++; hwr_grm_rec.sl_seq = ++hwr_grm_rec.seq; hwr_grm_rec.sl_if = interface; hwr_grm_rec.sl_type = type;
	memcpy(hwr_grm_rec.sl_mac, client_mac, 6);
	if (interface->bm_sta_map != NULL) {
		snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
		hwr_bm_sta_list_t *e = (hwr_bm_sta_list_t *)hwr_grm_hash_map_get(interface->bm_sta_map, key);
		if (e != NULL) {
			e->type &= ~type;
			if (!e->type) {
				for (int i = 0; i < interface->bm_sta_map->n; i++) if (interface->bm_sta_map->data[i] == e) interface->bm_sta_map->data[i] = NULL;
				hwr_grm_rec.freed = e;
				__asan_poison_memory_region(e, sizeof(*e));       /* free(): any later use of the entry is an error */
			}
		}
	}
}
extern "C" int hwr_grm_kick_device(hwr_grm_if_t *interface, mac_address_t addr)
{
	hwr_grm_rec.kick_calls++; hwr_grm_rec.kick_if = interface;
	memcpy(hwr_grm_rec.kick_mac, addr, 6);              /* nla_put(..., sizeof(mac_address_t), addr) */
	return g_kick_ret;
}

#define NM  { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }
#define CS  BM_STA_TYPE_CLIENT_SET
/* name, group, ap, mac, null_mask, entry_type, other_entry, map_null, kick_ret, del_ret, calls, check_log, expected_ret, expect_del, expect_removed, expect_kick, forked */
hwr_grm_case_t wifi_hal_steering_clientRemove_suite[] = {
	/* ---- entry present (client set by the API): removed, kicked ---- */
	{ "ap_0_entry_removed",    1, 0, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	{ "ap_1_entry_removed",    1, 1, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	{ "ap_2_entry_removed",    1, 2, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	{ "ap_3_entry_removed",    1, 3, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	/* ---- entry also created by an association: only the client-set bit is cleared ---- */
	{ "entry_also_assoc_kept", 1, 1, NM, 0, CS | 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0 },
	/* ---- no entry: nothing to delete, the client is still kicked ---- */
	{ "no_entry_only_kick",    1, 1, NM, 0, 0, 0, 0, 0, 0, 1, 0,  0, 0, 0, 1, 0 },
	{ "bm_sta_map_null_only_kick", 1, 2, NM, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0 },
	{ "other_client_entry_untouched", 1, 1, NM, 0, CS, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0 },
	{ "only_other_client_entry_present", 1, 1, NM, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0 },
	/* ---- unknown AP: error, nothing called ---- */
	{ "ap_4_unknown",          1, 4, NM, 0, CS, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0 },
	{ "ap_minus_1_unknown",    1, -1, NM, 0, CS, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0 },
	{ "ap_int_max_unknown",    1, INT_MAX, NM, 0, CS, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0 },
	{ "ap_int_min_unknown",    1, INT_MIN, NM, 0, CS, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0 },
	/* ---- kick / mac-list results ---- */
	{ "kick_fails_entry_still_removed", 1, 1, NM, 0, CS, 0, 0, -1, 0, 1, 0, -1, 1, 1, 1, 0 },
	{ "kick_fails_no_entry",   1, 1, NM, 0, 0, 0, 0, -1, 0, 1, 0, -1, 0, 0, 1, 0 },
	{ "del_mac_list_fails_entry_still_removed", 1, 1, NM, 0, CS, 0, 0, 0, -1, 1, 0, 0, 1, 1, 1, 0 },
	/* ---- group index is not used (design note, not counted) ---- */
	{ "group_0",               0, 1, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	{ "group_7",               7, 1, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	{ "group_8_not_validated", 8, 1, NM, 0, CS, 0, 0, 0, 0, 1, 0,  0, 1, 1, 1, 0 },
	{ "group_255_not_validated", 255, 1, NM, 0, CS, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0 },
	{ "group_uint_max_not_validated", UINT_MAX, 1, NM, 0, CS, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0 },
	/* ---- MAC variants ---- */
	{ "mac_all_zero",          1, 1, { 0, 0, 0, 0, 0, 0 }, 0, CS, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0 },
	{ "mac_broadcast",         1, 1, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 0, CS, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0 },
	{ "mac_multicast",         1, 1, { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 }, 0, CS, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3",     1, 2, NM, 0, CS, 0, 0, 0, 0, 3, 0,  0, 1, 1, 1, 0 },
	{ "log_has_remove_client_line", 1, 1, NM, 0, CS, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0 },
	/* ---- NULL client_mac behind a valid AP: crashes the unfixed function ---- */
	{ "client_mac_null_ap_1",  1, 1, NM, 1, CS, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 1 },
	{ "client_mac_null_ap_0_no_entry", 1, 0, NM, 1, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 1 },
	{ "client_mac_null_map_null", 1, 2, NM, 1, 0, 0, 1, 0, 0, 1, 0, -1, 0, 0, 0, 1 },
	{ "client_mac_null_group_7", 7, 3, NM, 1, CS, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 1 },
	/* ---- NULL client_mac but the AP lookup returns first: no crash ---- */
	{ "client_mac_null_ap_unknown", 1, 9, NM, 1, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0 },
	{ NULL, 0, 0, { 0 }, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

/*
 * UNIT TEST (input constructor): construct_wifi_hal_steering_clientSet
 *
 * wifi_hal_steering_clientSet(steeringgroupIndex, apIndex, client_mac, config) looks the AP up
 * (get_interface_by_vap_index; unknown -> RETURN_ERR), then under steering_data_lock creates / finds the
 * station entry with steering_add_stalist(interface, NULL, client_mac, BM_STA_TYPE_CLIENT_SET) (NULL ->
 * RETURN_ERR), copies *config into entry->bm_client_cfg, calls wifi_steering_del_mac_list() when both probe
 * RSSI marks are 0, and logs.  The group index is only logged.
 *
 * Stubs (below): the AP lookup knows apIndex 0..3 only; steering_add_stalist records its arguments (and reads
 * the 6 client_mac bytes like the real one) and returns the runner-owned station slab or NULL;
 * wifi_steering_del_mac_list records its arguments and returns a configurable result.
 * Inputs crossed: AP 0..3, unknown APs (4, -1, INT_MAX, INT_MIN), groups 0, 7, 8, 255, UINT_MAX (group is not
 * validated by the original: reported as a design note, expected RETURN_OK), steering_add_stalist failing,
 * distinct and extreme config values (UINT_MAX), probe HWM/LWM zero / non-zero combinations with
 * wifi_steering_del_mac_list OK and failing, MAC variants, repeated calls, log lines, and NULL client_mac /
 * NULL config / both (these crash the unfixed function: forked rows; with an unknown AP they return before
 * the pointer is used: plain rows).  Expected result for NULL pointers is RETURN_ERR with no station entry
 * created.  A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gcs.h"

hwr_gcs_rec_t hwr_gcs_rec;
static hwr_gcs_interface_t g_ifs[4] = { { 0 }, { 1 }, { 2 }, { 3 } };
static hwr_bm_sta_list_t *g_sta; static int g_add_fail, g_del_ret;

extern "C" hwr_gcs_interface_t *hwr_gcs_get_interface(unsigned int vap_index) { return vap_index < 4 ? &g_ifs[vap_index] : NULL; }
extern "C" hwr_bm_sta_list_t *hwr_gcs_add_stalist(hwr_gcs_interface_t *interface, char *ssid, mac_address_t client_mac, uint8_t type)
{
	hwr_gcs_rec.add_calls++; hwr_gcs_rec.add_if = interface; hwr_gcs_rec.add_ssid = ssid; hwr_gcs_rec.add_type = type;
	memcpy(hwr_gcs_rec.add_mac, client_mac, 6);         /* the real function reads the MAC too */
	return g_add_fail ? NULL : g_sta;
}
extern "C" int hwr_gcs_del_mac_list(uint32_t vap_index, hwr_bm_sta_list_t *sta_info) { hwr_gcs_rec.del_calls++; hwr_gcs_rec.del_vap = vap_index; hwr_gcs_rec.del_sta = sta_info; return g_del_ret; }
void hwr_gcs_configure(hwr_bm_sta_list_t *sta, int add_fail, int del_ret) { memset(&hwr_gcs_rec, 0, sizeof(hwr_gcs_rec)); g_sta = sta; g_add_fail = add_fail; g_del_ret = del_ret; }

#define NM  { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }
#define CF  { 5, 6, 7, 8, 9, 10, 11, 12 }
#define CZ  { 0, 0, 5, 6, 7, 8, 9, 10 }               /* both probe marks 0 */
/* name, group, ap, mac, cfg, null_mask, add_fail, del_ret, calls, check_log, expected_ret, expect_add, expect_del, forked */
hwr_gcs_case_t wifi_hal_steering_clientSet_suite[] = {
	/* ---- AP lookup ---- */
	{ "ap_0",                  1, 0, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "ap_1",                  1, 1, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "ap_2",                  1, 2, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "ap_3",                  1, 3, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "ap_4_unknown",          1, 4, NM, CF, 0, 0, 0, 1, 0, -1, 0, 0, 0 },
	{ "ap_minus_1_unknown",    1, -1, NM, CF, 0, 0, 0, 1, 0, -1, 0, 0, 0 },
	{ "ap_int_max_unknown",    1, INT_MAX, NM, CF, 0, 0, 0, 1, 0, -1, 0, 0, 0 },
	{ "ap_int_min_unknown",    1, INT_MIN, NM, CF, 0, 0, 0, 1, 0, -1, 0, 0, 0 },
	/* ---- group index: only logged (design note, not counted) ---- */
	{ "group_0",               0, 1, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "group_7",               7, 1, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "group_8_not_validated", 8, 1, NM, CF, 0, 0, 0, 1, 0,  0, 1, 0, 0 },
	{ "group_255_not_validated", 255, 1, NM, CF, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	{ "group_uint_max_not_validated", UINT_MAX, 1, NM, CF, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	/* ---- station entry creation fails ---- */
	{ "add_stalist_fails",     1, 1, NM, CF, 0, 1, 0, 1, 0, -1, 1, 0, 0 },
	{ "add_stalist_fails_probe_zero", 1, 2, NM, CZ, 0, 1, 0, 1, 0, -1, 1, 0, 0 },
	/* ---- config is stored as given ---- */
	{ "config_distinct_values", 1, 1, NM, { 1, 2, 3, 4, 5, 6, 7, 8 }, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	{ "config_uint_max",       1, 1, NM, { UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX }, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	{ "config_probe_hwm_only", 1, 1, NM, { 9, 0, 1, 1, 1, 1, 1, 1 }, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	{ "config_probe_lwm_only", 1, 1, NM, { 0, 9, 1, 1, 1, 1, 1, 1 }, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	/* ---- both probe marks 0: the client is removed from the MAC list ---- */
	{ "probe_zero_del_ok",     1, 1, NM, CZ, 0, 0, 0, 1, 0,  0, 1, 1, 0 },
	{ "probe_zero_del_fails",  1, 1, NM, CZ, 0, 0, -1, 1, 0, 0, 1, 1, 0 },
	{ "probe_zero_all_zero_cfg", 2, 3, NM, { 0, 0, 0, 0, 0, 0, 0, 0 }, 0, 0, 0, 1, 0, 0, 1, 1, 0 },
	/* ---- MAC variants ---- */
	{ "mac_all_zero",          1, 1, { 0, 0, 0, 0, 0, 0 }, CF, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	{ "mac_broadcast",         1, 1, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, CF, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	{ "mac_multicast",         1, 1, { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 }, CF, 0, 0, 0, 1, 0, 0, 1, 0, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3",     1, 2, NM, CF, 0, 0, 0, 3, 0,  0, 1, 0, 0 },
	{ "log_has_group_vap_client_and_rssi_lines", 6, 1, NM, CF, 0, 0, 0, 1, 1, 0, 1, 0, 0 },
	{ "log_has_remove_mac_line", 1, 1, NM, CZ, 0, 0, 0, 1, 2, 0, 1, 1, 0 },
	/* ---- NULL pointers behind a valid AP: crash the unfixed function ---- */
	{ "config_null",           1, 1, NM, CF, 2, 0, 0, 1, 0, -1, 0, 0, 1 },
	{ "client_mac_null",       1, 1, NM, CF, 1, 0, 0, 1, 0, -1, 0, 0, 1 },
	{ "client_mac_and_config_null", 1, 1, NM, CF, 3, 0, 0, 1, 0, -1, 0, 0, 1 },
	{ "config_null_ap_3",      0, 3, NM, CF, 2, 0, 0, 1, 0, -1, 0, 0, 1 },
	/* ---- NULL pointers but an earlier check returns first: no crash ---- */
	{ "config_null_ap_unknown", 1, 9, NM, CF, 2, 0, 0, 1, 0, -1, 0, 0, 0 },
	{ "client_mac_null_ap_unknown", 1, 9, NM, CF, 1, 0, 0, 1, 0, -1, 0, 0, 0 },
	{ NULL, 0, 0, { 0 }, { 0 }, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

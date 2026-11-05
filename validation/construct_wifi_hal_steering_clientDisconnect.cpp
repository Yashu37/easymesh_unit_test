/*
 * UNIT TEST (input constructor): construct_wifi_hal_steering_clientDisconnect
 *
 * wifi_hal_steering_clientDisconnect(steeringgroupIndex, apIndex, client_mac, type, reason) logs, looks the AP up
 * (unknown -> RETURN_ERR) and, for DISCONNECT_TYPE_DEAUTH / DISASSOC, calls
 * ap_sta_disconnect(&interface->u.ap.hapd, NULL, client_mac, reason) under hapd_lock and returns RETURN_OK;
 * any other type returns RETURN_ERR.
 *
 * Stubs (below): the AP lookup knows apIndex 0..3 and returns the runner-owned interface; ap_sta_disconnect
 * models libhostap's: it records its arguments and the lock state, and with a non-NULL address it reads
 * hapd->conf->iface (wpa_printf / hostapd_drv_sta_deauth); with a NULL address it returns without doing
 * anything.  For an AP interface hapd->conf is valid; for a STA VAP the same bytes hold STA state (0xA5).
 * Inputs crossed: DEAUTH / DISASSOC on APs 0..3, every other type (UNKNOWN 0, RECONNECT 3, 4, 255, -1, INT_MAX,
 * INT_MIN), unknown APs (4, -1, INT_MAX, INT_MIN), groups 0, 7, 8, 255, UINT_MAX (only logged: design note),
 * reasons 0, 1, 2, 3, 7, 65535 and 65536 / UINT_MAX (hostapd takes a u16: design note), MAC variants,
 * repeated calls, the log line, a NULL client_mac (silently "succeeds" in the unfixed function) and a STA VAP
 * (crashes the unfixed function: forked rows).  Expected result for NULL client_mac and for a STA VAP is
 * RETURN_ERR with ap_sta_disconnect not called.  A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gsd.h"

hwr_gsd_rec_t hwr_gsd_rec;
static hwr_gsd_if_t *g_if;

void hwr_gsd_configure(hwr_gsd_if_t *iface) { memset(&hwr_gsd_rec, 0, sizeof(hwr_gsd_rec)); g_if = iface; }
extern "C" hwr_gsd_if_t *hwr_gsd_get_interface(unsigned int vap_index) { return vap_index < 4 ? g_if : NULL; }
extern "C" void hwr_gsd_ap_sta_disconnect(hwr_gsd_hostapd *hapd, void *sta, const unsigned char *addr, uint16_t reason)
{
	hwr_gsd_rec.calls++; hwr_gsd_rec.hapd = hapd; hwr_gsd_rec.sta = sta; hwr_gsd_rec.reason = reason;
	hwr_gsd_rec.locked_in_call = pthread_mutex_trylock(&hwr_gsd_world.hapd_lock) != 0;      /* EBUSY: held by the caller */
	if (!hwr_gsd_rec.locked_in_call) pthread_mutex_unlock(&hwr_gsd_world.hapd_lock);
	hwr_gsd_rec.addr_null = (addr == NULL);
	if (addr) {
		volatile char c = hapd->conf->iface[0]; (void)c;              /* hapd->conf->iface in wpa_printf / the driver call */
		memcpy(hwr_gsd_rec.addr, addr, 6);
	}
}

#define NM  { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }
#define DIS 1        /* DISCONNECT_TYPE_DISASSOC */
#define DEA 2        /* DISCONNECT_TYPE_DEAUTH   */
/* name, group, ap, mac, null_mask, type, reason, sta_mode, calls, check_log, expected_ret, expect_call, forked */
hwr_gsd_case_t wifi_hal_steering_clientDisconnect_suite[] = {
	/* ---- supported types on every known AP ---- */
	{ "ap_0_deauth",           1, 0, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "ap_1_deauth",           1, 1, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "ap_2_deauth",           1, 2, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "ap_3_deauth",           1, 3, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "ap_0_disassoc",         1, 0, NM, 0, DIS, 8, 0, 1, 0,  0, 1, 0 },
	{ "ap_3_disassoc",         1, 3, NM, 0, DIS, 8, 0, 1, 0,  0, 1, 0 },
	/* ---- every other type: error, nothing called ---- */
	{ "type_unknown_0",        1, 1, NM, 0, 0, 3, 0, 1, 0, -1, 0, 0 },
	{ "type_reconnect_3",      1, 1, NM, 0, 3, 3, 0, 1, 0, -1, 0, 0 },
	{ "type_4",                1, 1, NM, 0, 4, 3, 0, 1, 0, -1, 0, 0 },
	{ "type_255",              1, 1, NM, 0, 255, 3, 0, 1, 0, -1, 0, 0 },
	{ "type_minus_1",          1, 1, NM, 0, -1, 3, 0, 1, 0, -1, 0, 0 },
	{ "type_int_max",          1, 1, NM, 0, INT_MAX, 3, 0, 1, 0, -1, 0, 0 },
	{ "type_int_min",          1, 1, NM, 0, INT_MIN, 3, 0, 1, 0, -1, 0, 0 },
	/* ---- unknown AP: error, nothing called ---- */
	{ "ap_4_unknown",          1, 4, NM, 0, DEA, 3, 0, 1, 0, -1, 0, 0 },
	{ "ap_minus_1_unknown",    1, -1, NM, 0, DEA, 3, 0, 1, 0, -1, 0, 0 },
	{ "ap_int_max_unknown",    1, INT_MAX, NM, 0, DEA, 3, 0, 1, 0, -1, 0, 0 },
	{ "ap_int_min_unknown",    1, INT_MIN, NM, 0, DEA, 3, 0, 1, 0, -1, 0, 0 },
	/* ---- group index: only logged (design note, not counted) ---- */
	{ "group_0",               0, 1, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "group_7",               7, 1, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "group_8_not_validated", 8, 1, NM, 0, DEA, 3, 0, 1, 0,  0, 1, 0 },
	{ "group_255_not_validated", 255, 1, NM, 0, DEA, 3, 0, 1, 0, 0, 1, 0 },
	{ "group_uint_max_not_validated", UINT_MAX, 1, NM, 0, DEA, 3, 0, 1, 0, 0, 1, 0 },
	/* ---- reason codes are forwarded (hostapd takes a u16: values above 65535 are truncated, design note) ---- */
	{ "reason_0",              1, 1, NM, 0, DEA, 0, 0, 1, 0,  0, 1, 0 },
	{ "reason_1",              1, 1, NM, 0, DEA, 1, 0, 1, 0,  0, 1, 0 },
	{ "reason_7",              1, 1, NM, 0, DIS, 7, 0, 1, 0,  0, 1, 0 },
	{ "reason_65535",          1, 1, NM, 0, DEA, 65535, 0, 1, 0, 0, 1, 0 },
	{ "reason_65536_truncated_to_0", 1, 1, NM, 0, DEA, 65536, 0, 1, 0, 0, 1, 0 },
	{ "reason_uint_max_truncated_to_65535", 1, 1, NM, 0, DEA, UINT_MAX, 0, 1, 0, 0, 1, 0 },
	/* ---- MAC variants / repeats / log ---- */
	{ "mac_all_zero",          1, 1, { 0, 0, 0, 0, 0, 0 }, 0, DEA, 3, 0, 1, 0, 0, 1, 0 },
	{ "mac_broadcast",         1, 1, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 0, DEA, 3, 0, 1, 0, 0, 1, 0 },
	{ "mac_multicast",         1, 1, { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 }, 0, DEA, 3, 0, 1, 0, 0, 1, 0 },
	{ "repeated_calls_x3",     1, 2, NM, 0, DEA, 3, 0, 3, 0,  0, 1, 0 },
	{ "log_has_enter_and_parameters", 6, 1, NM, 0, DEA, 15, 0, 1, 1, 0, 1, 0 },
	/* ---- NULL client_mac: ap_sta_disconnect does nothing, the unfixed function still returns RETURN_OK ---- */
	{ "client_mac_null_deauth", 1, 1, NM, 1, DEA, 3, 0, 1, 0, -1, 0, 0 },
	{ "client_mac_null_disassoc", 1, 2, NM, 1, DIS, 3, 0, 1, 0, -1, 0, 0 },
	{ "client_mac_null_type_unknown", 1, 1, NM, 1, 0, 3, 0, 1, 0, -1, 0, 0 },
	{ "client_mac_null_ap_unknown", 1, 9, NM, 1, DEA, 3, 0, 1, 0, -1, 0, 0 },
	/* ---- STA VAP: u.ap.hapd is not a hostapd instance there (crashes the unfixed function) ---- */
	{ "sta_vap_deauth",        1, 1, NM, 0, DEA, 3, 1, 1, 0, -1, 0, 1 },
	{ "sta_vap_disassoc",      1, 2, NM, 0, DIS, 3, 1, 1, 0, -1, 0, 1 },
	{ "sta_vap_deauth_ap_0",   0, 0, NM, 0, DEA, 1, 1, 1, 0, -1, 0, 1 },
	{ "sta_vap_client_mac_null", 1, 1, NM, 1, DEA, 3, 1, 1, 0, -1, 0, 0 },
	{ "sta_vap_type_unknown",  1, 1, NM, 0, 0, 3, 1, 1, 0, -1, 0, 0 },
	{ NULL, 0, 0, { 0 }, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

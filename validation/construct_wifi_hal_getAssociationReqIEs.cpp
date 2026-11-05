/*
 * UNIT TEST (input constructor): construct_wifi_hal_getAssociationReqIEs
 *
 * wifi_hal_getAssociationReqIEs(apIndex, clientMacAddress, req_ies, req_ies_size, req_ies_len) looks the AP up
 * (unknown -> RETURN_ERR), then under hapd_lock finds the client with ap_get_sta(&interface->u.ap.hapd, mac),
 * rejects a buffer smaller than station->assoc_req_len, copies the association request IEs and returns their
 * length in *req_ies_len.
 *
 * Stubs (below): the AP lookup knows apIndex 0..3 and returns the runner-owned interface; ap_get_sta models
 * libhostap's: it hashes (reads) the 6 MAC bytes, reads hapd->conf (the station table; for a STA VAP the same
 * bytes hold STA state: 0xA5) and returns the registered station or NULL.
 * Inputs crossed: APs 0..3 and unknown APs (4, UINT_MAX, INT_MAX, 0x80000000), association request lengths 0
 * (NULL pointer), 1, 40, 64, 200, 1024, buffer sizes equal to the length, larger (2000, UINT_MAX), one byte too
 * small, zero, a second registered client, MAC variants, repeated calls, the log lines, an unknown client
 * (NULL station), a STA VAP, and NULL clientMacAddress / req_ies / req_ies_len.  Unfixed crashes (unknown
 * client, STA VAP, NULL pointers) run forked.  Expected result is RETURN_ERR for every failing input, with
 * *req_ies_len and the buffer untouched and hapd_lock released.  A FAIL is a finding.
 */
#include <limits.h>
#include "hwr_gai.h"

hwr_gai_rec_t hwr_gai_rec;
static hwr_gai_if_t *g_if;

void hwr_gai_configure(hwr_gai_if_t *iface) { memset(&hwr_gai_rec, 0, sizeof(hwr_gai_rec)); g_if = iface; }
extern "C" hwr_gai_if_t *hwr_gai_get_interface(unsigned int vap_index) { return vap_index < 4 ? g_if : NULL; }
extern "C" hwr_gai_sta_info *hwr_gai_ap_get_sta(hwr_gai_hostapd *hapd, const u8 *addr)
{
	hwr_gai_rec.calls++; hwr_gai_rec.hapd = hapd;
	unsigned h = addr[0] ^ addr[1] ^ addr[2] ^ addr[3] ^ addr[4] ^ addr[5];      /* STA_HASH(): reads all 6 MAC bytes */
	(void)h;
	memcpy(hwr_gai_rec.addr, addr, 6);
	for (int i = 0; i < hapd->conf->n; i++)                                      /* hapd->sta_hash[...] */
		if (!memcmp(hapd->conf->mac[i], addr, 6)) return hapd->conf->sta[i];
	return NULL;
}

#define NM  { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 }
/* name, ap, mac, null_mask, sta_mode, client, assoc_len, req_size, other_present, calls, check_log, expected_ret, forked */
hwr_gai_case_t wifi_hal_getAssociationReqIEs_suite[] = {
	/* ---- APs 0..3, client present ---- */
	{ "ap_0",                  0, NM, 0, 0, 1, 40, 64, 0, 1, 0,  0, 0 },
	{ "ap_1",                  1, NM, 0, 0, 1, 40, 64, 0, 1, 0,  0, 0 },
	{ "ap_2",                  2, NM, 0, 0, 1, 40, 64, 0, 1, 0,  0, 0 },
	{ "ap_3",                  3, NM, 0, 0, 1, 40, 64, 0, 1, 0,  0, 0 },
	/* ---- unknown AP ---- */
	{ "ap_4_unknown",          4, NM, 0, 0, 1, 40, 64, 0, 1, 0, -1, 0 },
	{ "ap_uint_max_unknown",   UINT_MAX, NM, 0, 0, 1, 40, 64, 0, 1, 0, -1, 0 },
	{ "ap_int_max_unknown",    INT_MAX, NM, 0, 0, 1, 40, 64, 0, 1, 0, -1, 0 },
	{ "ap_0x80000000_unknown", 0x80000000u, NM, 0, 0, 1, 40, 64, 0, 1, 0, -1, 0 },
	/* ---- IE lengths with an exactly sized buffer ---- */
	{ "len_0_size_0",          1, NM, 0, 0, 1, 0, 0, 0, 1, 0,  0, 0 },
	{ "len_1_exact",           1, NM, 0, 0, 1, 1, 1, 0, 1, 0,  0, 0 },
	{ "len_40_exact",          1, NM, 0, 0, 1, 40, 40, 0, 1, 0,  0, 0 },
	{ "len_64_exact",          1, NM, 0, 0, 1, 64, 64, 0, 1, 0,  0, 0 },
	{ "len_200_exact",         1, NM, 0, 0, 1, 200, 200, 0, 1, 0,  0, 0 },
	{ "len_1024_exact",        1, NM, 0, 0, 1, 1024, 1024, 0, 1, 0,  0, 0 },
	/* ---- larger buffers ---- */
	{ "size_2000_len_40",      1, NM, 0, 0, 1, 40, 2000, 0, 1, 0,  0, 0 },
	{ "size_uint_max_len_40",  1, NM, 0, 0, 1, 40, UINT_MAX, 0, 1, 0,  0, 0 },
	{ "size_1_len_0",          1, NM, 0, 0, 1, 0, 1, 0, 1, 0,  0, 0 },
	/* ---- buffer too small: RETURN_ERR, nothing written ---- */
	{ "size_one_byte_too_small", 1, NM, 0, 0, 1, 40, 39, 0, 1, 2, -1, 0 },
	{ "size_0_len_40",         1, NM, 0, 0, 1, 40, 0, 0, 1, 0, -1, 0 },
	{ "size_1_len_1024",       1, NM, 0, 0, 1, 1024, 1, 0, 1, 0, -1, 0 },
	/* ---- two clients: the right one is found ---- */
	{ "two_clients_target_found", 2, NM, 0, 0, 1, 40, 64, 1, 1, 0,  0, 0 },
	/* ---- MAC variants ---- */
	{ "mac_all_zero",          1, { 0, 0, 0, 0, 0, 0 }, 0, 0, 1, 40, 64, 0, 1, 0, 0, 0 },
	{ "mac_broadcast",         1, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 0, 0, 1, 40, 64, 0, 1, 0, 0, 0 },
	{ "mac_multicast",         1, { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 }, 0, 0, 1, 40, 64, 0, 1, 0, 0, 0 },
	/* ---- repeats / log ---- */
	{ "repeated_calls_x3",     2, NM, 0, 0, 1, 40, 64, 0, 3, 0,  0, 0 },
	{ "log_has_function_name_and_enter", 1, NM, 0, 0, 1, 40, 64, 0, 1, 1,  0, 0 },
	/* ---- unknown client behind a valid AP: ap_get_sta returns NULL, the function reads station->assoc_req_len ---- */
	{ "client_not_registered", 1, NM, 0, 0, 0, 40, 64, 0, 1, 0, -1, 1 },
	{ "only_another_client_registered", 2, NM, 0, 0, 2, 40, 64, 1, 1, 0, -1, 1 },
	{ "client_not_registered_ap_3_size_0", 3, NM, 0, 0, 0, 0, 0, 0, 1, 0, -1, 1 },
	/* ---- STA VAP: u.ap.hapd is not a hostapd instance there ---- */
	{ "sta_vap_client_known",  1, NM, 0, 1, 1, 40, 64, 0, 1, 0, -1, 1 },
	{ "sta_vap_ap_0",          0, NM, 0, 1, 0, 40, 64, 0, 1, 0, -1, 1 },
	{ "sta_vap_unknown_ap",    9, NM, 0, 1, 1, 40, 64, 0, 1, 0, -1, 0 },
	/* ---- NULL pointers behind a valid AP / client ---- */
	{ "client_mac_null",       1, NM, 1, 0, 1, 40, 64, 0, 1, 0, -1, 1 },
	{ "req_ies_null",          1, NM, 2, 0, 1, 40, 64, 0, 1, 0, -1, 1 },
	{ "req_ies_len_null",      1, NM, 4, 0, 1, 40, 64, 0, 1, 0, -1, 1 },
	{ "all_three_null",        1, NM, 7, 0, 1, 40, 64, 0, 1, 0, -1, 1 },
	{ "req_ies_null_too_small_size", 1, NM, 2, 0, 1, 40, 10, 0, 1, 0, -1, 0 },
	/* ---- NULL pointers but the AP lookup returns first ---- */
	{ "client_mac_null_unknown_ap", 9, NM, 1, 0, 1, 40, 64, 0, 1, 0, -1, 0 },
	{ "req_ies_len_null_unknown_ap", 9, NM, 4, 0, 1, 40, 64, 0, 1, 0, -1, 0 },
	{ NULL, 0, { 0 }, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

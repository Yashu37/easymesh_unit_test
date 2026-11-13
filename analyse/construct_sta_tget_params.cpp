/*
 * TEST CASES / CONSTRUCTOR: construct_sta_tget_params
 *
 * root lives in root_store at offset STP_ROOT_LEFT (runner poisons the bytes in front of it and past its NUL);
 * root "LONG" is a 600-character prefix. The BSS handed to the handler is 02:00:00:00:00:01. One data model whose
 * STA map holds the STAs of the case (S(assoc, bss, fb_len, ht, vht): MAC 02:00:00:01:00:<n>, BSSID
 * 02:00:00:00:00:<bss>, frame_body = bytes 0,1,2,... of length fb_len, n = position + 1); numerics: dl 111,
 * ul 222, util rx 3 / tx 4, est dl 555 / ul 666, rcpi 77, last_conn 888, bytes 1001/1002, pkts 2001/2002,
 * errors 3/4, retrans 5. The recorded lines are "idx:name=value"; idx numbers only the listed STAs
 * (associated, BSSID equal to the BSS), 1-based.
 *
 * Expected: always bus_error_success. The last 3 cases (frame_body_len above the 512-byte frame_body[]) ABORTED on
 * the original handler (base64_encode(si->frame_body, si->frame_body_len)); with fix 1 the length is clamped to
 * EM_MAX_FRAME_BODY_LEN and they pass as clamp_*.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sta_tget_params.h"

namespace stp {

alignas(16) char root_store[STP_ROOT_LEFT + STP_ROOT_SZ + 64];

#define R "Device.WiFi.DataElements.Network.Device.1.Radio.1.BSS.1.STA."
#define S(a, b, f, h, v) {a, b, f, h, v}
#define E0 S(false, 0, 0, NULL, NULL)
#define ONE {S(true, 1, 3, "htcap", "vhtcap"), E0, E0, E0}
#define T1(n, has) {n, R, ONE, 1, has, NULL, false}
#define FB(n, len) {n, R, {S(true, 1, len, "htcap", "vhtcap"), E0, E0, E0}, 1, NULL, NULL, false}
#define CLFB(n, len) {n, R, {S(true, 1, len, "htcap", "vhtcap"), E0, E0, E0}, 1, "1:ClientCapabilities=AAECAwQFBgcI", NULL, false}

test_case_t suite[] = {
 /* ---- one associated STA: every property ---- */
 T1("ok_mac", "1:MACAddress=02:00:00:01:00:01\n"),
 T1("ok_ht_caps", "1:HTCapabilities=htcap\n"),
 T1("ok_vht_caps", "1:VHTCapabilities=vhtcap\n"),
 T1("ok_client_caps_len3", "1:ClientCapabilities=AAEC\n"),
 T1("ok_wifi6_first", "1:WiFi6Capabilities.HE160=1\n"),
 T1("ok_wifi6_second", "1:WiFi6Capabilities.HE8080=0\n"),
 T1("ok_wifi6_last", "1:WiFi6Capabilities.AnticipatedChannelUsage=1\n"),
 T1("ok_rates_and_utilization", "1:LastDataDownlinkRate=111\n1:LastDataUplinkRate=222\n1:UtilizationReceive=3\n1:UtilizationTransmit=4\n"),
 T1("ok_est_rates_signal_connect", "1:EstMACDataRateDownlink=555\n1:EstMACDataRateUplink=666\n1:SignalStrength=77\n1:LastConnectTime=888\n"),
 T1("ok_bytes_and_packets", "1:BytesSent=1001\n1:BytesReceived=1002\n1:PacketsSent=2001\n1:PacketsReceived=2002\n"),
 T1("ok_errors_and_retrans", "1:ErrorsSent=3\n1:ErrorsReceived=4\n1:RetransCount=5\n"),
 T1("ok_fixed_tail_properties", "1:IPV4Address=\n1:IPV6Address=\n1:Hostname=\n1:PairwiseAKM=0\n1:PairwiseCipher=0\n1:RSNCapabilities=0\n"),
 /* ---- frame body (ClientCapabilities, base64) ---- */
 {"ok_client_caps_empty", R, {S(true, 1, 0, "htcap", "vhtcap"), E0, E0, E0}, 1, "1:ClientCapabilities=\n", NULL, false},
 {"ok_client_caps_len1", R, {S(true, 1, 1, "htcap", "vhtcap"), E0, E0, E0}, 1, "1:ClientCapabilities=AA==\n", NULL, false},
 {"ok_client_caps_len2", R, {S(true, 1, 2, "htcap", "vhtcap"), E0, E0, E0}, 1, "1:ClientCapabilities=AAE=\n", NULL, false},
 {"ok_client_caps_full_512", R, {S(true, 1, 512, "htcap", "vhtcap"), E0, E0, E0}, 1, "1:ClientCapabilities=AAECAwQFBgcI", NULL, false},
 {"ok_client_caps_511", R, {S(true, 1, 511, "htcap", "vhtcap"), E0, E0, E0}, 1, "1:ClientCapabilities=AAECAwQFBgcI", NULL, false},
 /* ---- which STAs are listed and how they are numbered ---- */
 {"ok_no_sta", R, {E0, E0, E0, E0}, 0, NULL, "MACAddress", false},
 {"ok_not_associated_skipped", R, {S(false, 1, 3, "h", "v"), E0, E0, E0}, 0, NULL, "MACAddress", false},
 {"ok_other_bss_skipped", R, {S(true, 2, 3, "h", "v"), E0, E0, E0}, 0, NULL, "MACAddress", false},
 {"ok_two_sta_numbered", R, {S(true, 1, 3, "h", "v"), S(true, 1, 3, "h", "v"), E0, E0}, 2, "2:MACAddress=02:00:00:01:00:02\n", NULL, false},
 {"ok_numbering_skips_not_associated", R, {S(false, 1, 3, "h", "v"), S(true, 1, 3, "h", "v"), E0, E0}, 1, "1:MACAddress=02:00:00:01:00:02\n", NULL, false},
 {"ok_numbering_skips_other_bss", R, {S(true, 1, 3, "h", "v"), S(true, 2, 3, "h", "v"), S(true, 1, 3, "h", "v"), E0}, 2, "2:MACAddress=02:00:00:01:00:03\n", NULL, false},
 {"ok_four_sta", R, {S(true, 1, 3, "h", "v"), S(true, 1, 3, "h", "v"), S(true, 1, 3, "h", "v"), S(true, 1, 3, "h", "v")}, 4, "4:MACAddress=02:00:00:01:00:04\n", NULL, false},
 {"ok_long_root", "LONG", ONE, 1, "1:MACAddress=02:00:00:01:00:01\n", NULL, false},
 /* ---- were CRASH cases on the original handler: frame_body_len above the 512-byte frame_body[] (now clamped to 512) ---- */
 CLFB("clamp_frame_body_len_513", 513),
 CLFB("clamp_frame_body_len_600", 600),
 CLFB("clamp_frame_body_len_65534", 65534),

 { NULL, NULL, {E0, E0, E0, E0}, 0, NULL, NULL, false }  /* sentinel */
};

static dm_sta_t *g_sta[STP_MAXSTA];
static sta_map_t g_map;

void construct_input(const test_case_t *tc)
{
    memset(root_store, 0, sizeof(root_store));
    if (!strcmp(tc->root, "LONG")) memset(root_store + STP_ROOT_LEFT, 'a', 600);
    else snprintf(root_store + STP_ROOT_LEFT, STP_ROOT_SZ, "%s", tc->root);
    g_rec[0] = '\0'; g_rows = 0;
    memset(&g_map, 0, sizeof(g_map));
    for (int i = 0; i < STP_MAXSTA; i++) {
        g_sta[i] = NULL;
        const sta_spec_t *s = &tc->sta[i];
        if (!s->bss) continue;
        dm_sta_t *st = new dm_sta_t;
        memset((void *)st, 0, sizeof(*st));
        em_sta_info_t *si = &st->info;
        unsigned char id[6] = {2, 0, 0, 1, 0, (unsigned char)(i + 1)}, bs[6] = {2, 0, 0, 0, 0, s->bss};
        memcpy(si->id, id, 6); memcpy(si->bssid, bs, 6);
        si->associated = s->assoc;
        snprintf(si->ht_cap, sizeof(si->ht_cap), "%s", s->ht ? s->ht : "");
        snprintf(si->vht_cap, sizeof(si->vht_cap), "%s", s->vht ? s->vht : "");
        si->frame_body_len = (unsigned int)s->fb_len;
        for (int k = 0; k < EM_MAX_FRAME_BODY_LEN; k++) si->frame_body[k] = (unsigned char)k;
        si->last_dl_rate = 111; si->last_ul_rate = 222; si->util_rx = 3; si->util_tx = 4;
        si->est_dl_rate = 555; si->est_ul_rate = 666; si->rcpi = 77; si->last_conn_time = 888;
        si->bytes_tx = 1001; si->bytes_rx = 1002; si->pkts_tx = 2001; si->pkts_rx = 2002;
        si->errors_tx = 3; si->errors_rx = 4; si->retrans_count = 5;
        g_sta[i] = st; g_map.p[g_map.n++] = st;
    }
    g_dm = new dm_easy_mesh_t;
    g_dm->m_sta_map = &g_map;
}

void teardown(void)
{
    for (int i = 0; i < STP_MAXSTA; i++) { delete g_sta[i]; g_sta[i] = NULL; }
    delete g_dm; g_dm = NULL;
}

} /* namespace stp */

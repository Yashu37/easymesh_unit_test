/*
 * TEST CASES / CONSTRUCTOR: construct_em_send_action_frame
 *
 * query (beacon_query_params_t) lives at esaf_query_buf; the wifi_mgr stand-in
 * at esaf_mgr_buf. 1 radio / 2 vaps: vap0 bssid AA.. (mld_addr CC..), vap1
 * bssid BB.. . The radio oper params (country/opclass/channel) are in
 * esaf_radio_oper. esaf_* globals steer the radio/country/send stubs.
 *
 * Cases: match_bssid (bssid=BB -> vap1), match_mld (bssid=CC -> vap0 via MLD),
 * no_match, radio_null, country_fail, send_fail.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char esaf_mgr_buf[sizeof(wifi_mgr_t) + ESAF_PAD];
alignas(16) char esaf_query_buf[sizeof(beacon_query_params_t) + ESAF_PAD];
int esaf_num_radios, esaf_vap_present[8], esaf_radio_index, esaf_radio_null, esaf_country_fail, esaf_send_fail, esaf_send_calls;
wifi_vap_info_map_t esaf_vap_maps[8];
wifi_radio_operationParam_t esaf_radio_oper;

em_esaf_test_case_t em_send_action_frame_suite[] = {
    /* name          radio_null country_fail send_fail bssid_sel want_rc */
    { "match_bssid",    0,       0,           0,        'B',      0 },
    { "match_mld",      0,       0,           0,        'C',      0 },
    { "no_match",       0,       0,           0,        'F',     -1 },
    { "radio_null",     1,       0,           0,        'B',     -1 },
    { "country_fail",   0,       1,           0,        'B',     -1 },
    { "send_fail",      0,       0,           1,        'B',     -1 },
    { NULL, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_send_action_frame_input(const em_esaf_test_case_t *tc)
{
    memset(esaf_mgr_buf, 0, sizeof(esaf_mgr_buf));
    memset(esaf_query_buf, 0, sizeof(esaf_query_buf));
    memset(esaf_vap_maps, 0, sizeof(esaf_vap_maps));
    memset(&esaf_radio_oper, 0, sizeof(esaf_radio_oper));

    esaf_num_radios = 1;
    esaf_vap_present[0] = 1;
    esaf_vap_maps[0].num_vaps = 2;
    /* vap0 bssid AA.., mld_addr CC.. ; vap1 bssid BB.. */
    unsigned char aa[6] = {0xAA,0xbb,0xcc,0xdd,0xee,0x00}; unsigned char cc[6] = {0xCC,0xbb,0xcc,0xdd,0xee,0x00};
    unsigned char bb[6] = {0xBB,0xbb,0xcc,0xdd,0xee,0x00};
    esaf_vap_maps[0].vap_array[0].vap_index = 0;
    memcpy(esaf_vap_maps[0].vap_array[0].u.bss_info.bssid, aa, 6);
    memcpy(esaf_vap_maps[0].vap_array[0].u.bss_info.mld_info.common_info.mld_addr, cc, 6);
    esaf_vap_maps[0].vap_array[1].vap_index = 1;
    memcpy(esaf_vap_maps[0].vap_array[1].u.bss_info.bssid, bb, 6);

    esaf_radio_index = 0;
    esaf_radio_oper.countryCode = 1;
    esaf_radio_oper.operatingClass = 115;
    esaf_radio_oper.channel = 36;

    beacon_query_params_t *q = (beacon_query_params_t *)esaf_query_buf;
    unsigned char sm[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    memcpy(q->sta_mac, sm, 6);
    unsigned char sel[6];
    if (tc->bssid_sel == 'B')      memcpy(sel, bb, 6);
    else if (tc->bssid_sel == 'C') memcpy(sel, cc, 6);
    else { unsigned char ff[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; memcpy(sel, ff, 6); }
    memcpy(q->data.bssid, sel, 6);
    q->data.opClass = 115;
    q->data.channel = 36;
    q->data.channelReportPresent = 0;

    esaf_radio_null   = tc->radio_null;
    esaf_country_fail = tc->country_fail;
    esaf_send_fail    = tc->send_fail;
    esaf_send_calls   = 0;
}

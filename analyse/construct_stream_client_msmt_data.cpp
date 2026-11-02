/*
 * TEST CASES / CONSTRUCTOR: construct_stream_client_msmt_data
 *
 * act_monitor (scm_mgr_buf) carries active_msmt_map + curStepData.DestMac;
 * wifi_ctrl (scm_wctrl_buf) sets network_mode. An "existing" station may be
 * registered under the lower-case-from-to_sta_key key. ActiveMsmtFlag and a
 * NULL g_active_msmt are selectable.
 *
 * Cases: flag false (no-op), mgr NULL, NULL map, sta not found, sta found gw
 * (upload), sta found ext (pod_upload), hex MAC key.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   scm_slot_key[SCM_KEY_SZ + SCM_PAD];
size_t scm_key_len;
char   scm_key_seen[64];
char   scm_existing_key[32];
void  *scm_existing;
int    scm_mgr_null, scm_upload_calls, scm_pod_calls;
alignas(16) char scm_mgr_buf[sizeof(wifi_actvie_msmt_t) + SCM_PAD];
alignas(16) char scm_wctrl_buf[sizeof(wifi_ctrl_t) + SCM_PAD];
static blaster_hashmap_t scm_known;

stream_client_msmt_data_test_case_t stream_client_msmt_data_suite[] = {
    /* name           flag  mgr_null no_map  found  gw   mac0  up pod */
    { "flag_false",     0,   0,       0,     0,     1,   0x10, 0, 0 },
    { "mgr_null",       1,   1,       0,     0,     1,   0x10, 0, 0 },
    { "null_map",       1,   0,       1,     0,     1,   0x10, 0, 0 },
    { "not_found",      1,   0,       0,     0,     1,   0x10, 0, 0 },
    { "found_gw",       1,   0,       0,     1,     1,   0x10, 1, 0 },
    { "found_ext",      1,   0,       0,     1,     0,   0x10, 0, 1 },
    { "found_hexmac",   1,   0,       0,     1,     1,   0xaa, 1, 0 },

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_stream_client_msmt_data_input(const stream_client_msmt_data_test_case_t *tc)
{
    memset(scm_mgr_buf, 0, sizeof(scm_mgr_buf));
    memset(scm_wctrl_buf, 0, sizeof(scm_wctrl_buf));
    memset(&scm_known, 0, sizeof(scm_known));

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)scm_mgr_buf;
    for (int b = 0; b < 6; b++) g->curStepData.DestMac[b] = (unsigned char)(tc->mac0 + b);
    g->active_msmt_map = tc->no_map ? NULL : (void *)0x1;

    wifi_ctrl_t *c = (wifi_ctrl_t *)scm_wctrl_buf;
    c->network_mode = tc->gw ? 0 /*gw*/ : 1 /*ext*/;

    scm_existing = tc->found ? &scm_known : NULL;
    snprintf(scm_existing_key, sizeof(scm_existing_key), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)tc->mac0, (unsigned char)(tc->mac0+1), (unsigned char)(tc->mac0+2),
             (unsigned char)(tc->mac0+3), (unsigned char)(tc->mac0+4), (unsigned char)(tc->mac0+5));

    scm_mgr_null = tc->mgr_null;
    scm_key_len = 0;
    scm_key_seen[0] = 0;
    scm_upload_calls = scm_pod_calls = 0;
}

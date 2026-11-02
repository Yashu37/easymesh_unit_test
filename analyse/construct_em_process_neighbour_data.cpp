/*
 * TEST CASES / CONSTRUCTOR: construct_em_process_neighbour_data
 *
 * provider_response lives at epnd_resp_buf; the wifi_mgr stand-in at
 * epnd_mgr_buf. The epnd_* globals steer the stubbed prepare/publish/ssid
 * helpers and the BTM-pending state (g_btm_pending_valid / g_pending_btm).
 *
 * Cases: btm_populate (neighbors copied), btm_no_match (none match ->
 * neighbor_list_present false), btm_cap (>16 -> capped at EM_MAX_NEIGHBORS),
 * publish_path (no BTM -> publish), prepare_fail_btm (empty BTM -> RETURN_OK),
 * prepare_fail_nobtm / publish_fail / mgr_null (RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char epnd_mgr_buf[sizeof(wifi_mgr_t) + EPND_PAD];
alignas(16) char epnd_resp_buf[sizeof(wifi_provider_response_t) + EPND_PAD];
int epnd_mgr_null, epnd_prepare_fail, epnd_num_results, epnd_num_neighbors;
int epnd_publish_fail, epnd_publish_calls, epnd_vap_ssid_count, epnd_ssid_match_all;
int epnd_push_calls, epnd_stop_calls;
bool g_btm_pending_valid;
em_btm_req_ctrl_msg_t g_pending_btm;

em_epnd_test_case_t em_process_neighbour_data_suite[] = {
    /* name              mgrnull pfail nres nnbr btm matchall vapcnt pubfail want_ret want_nbr */
    { "btm_populate",       0,   0,   2,   2,   1,   1,       3,     0,      0,       4 },
    { "btm_no_match",       0,   0,   2,   2,   1,   0,       0,     0,      0,       0 },
    { "btm_cap",            0,   0,   5,   5,   1,   1,       3,     0,      0,      16 },
    { "publish_path",       0,   0,   2,   2,   0,   0,       3,     0,      0,       0 },
    { "prepare_fail_btm",   0,   1,   0,   0,   1,   0,       0,     0,      0,       0 },
    { "prepare_fail_nobtm", 0,   1,   0,   0,   0,   0,       0,     0,     -1,       0 },
    { "publish_fail",       0,   0,   2,   2,   0,   0,       3,     1,     -1,       0 },
    { "mgr_null",           1,   0,   0,   0,   0,   0,       0,     0,     -1,       0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_process_neighbour_data_input(const em_epnd_test_case_t *tc)
{
    memset(epnd_mgr_buf, 0, sizeof(epnd_mgr_buf));
    memset(epnd_resp_buf, 0, sizeof(epnd_resp_buf));
    memset(&g_pending_btm, 0, sizeof(g_pending_btm));

    epnd_mgr_null       = tc->mgr_null;
    epnd_prepare_fail   = tc->prepare_fail;
    epnd_num_results    = tc->num_results;
    epnd_num_neighbors  = tc->num_neighbors;
    epnd_publish_fail   = tc->publish_fail;
    epnd_vap_ssid_count = tc->vap_ssid_count;
    epnd_ssid_match_all = tc->ssid_match_all;
    epnd_publish_calls  = 0;
    epnd_push_calls     = 0;
    epnd_stop_calls     = 0;
    g_btm_pending_valid = tc->btm_pending ? true : false;
}

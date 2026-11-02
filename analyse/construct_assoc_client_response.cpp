/*
 * TEST CASES / CONSTRUCTOR: construct_assoc_client_response
 *
 * The provider_response lives at acr_resp_buf; its stat_pointer points at a
 * freshly malloc'd source of stat_array_size sta_data_t entries (so the READ
 * side of the memcpy is always valid -- only the WRITE into the fixed
 * assoc_stats[BSS_MAX_NUM_STATIONS] can overrun). client_assoc_stats is the
 * global target array. convert_vap_index_to_name / convert_vap_name_to_array_index
 * outcomes are driven by acr_convert_name_ok / acr_vap_array_index.
 *
 * Cases: safe_5, push_path (req mask set -> handle_ready_client_stats),
 * boundary_100 (exactly fills), zero_stats / convert_fail / vap_not_found
 * (RETURN_ERR), and overflow_200 (stat_array_size > capacity -> OOB write).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

client_assoc_stats_t client_assoc_stats[MAX_NUM_RADIOS];
alignas(16) char acr_mgr_buf[sizeof(wifi_mgr_t) + ACR_PAD];
alignas(16) char acr_resp_buf[sizeof(wifi_provider_response_t) + ACR_PAD];
void *acr_stat_pointer;
int   acr_vap_array_index;
int   acr_convert_name_ok;
int   acr_ready_calls;

em_acr_test_case_t assoc_client_response_suite[] = {
    /* name            radio vap stat_sz conv_ok vap_arr req_mask want_ret crash */
    { "safe_5",          0,  0,   5,      1,      0,      0,       0,      0 },
    { "push_path",       0,  1,   3,      1,      1,      1,       0,      0 },
    { "boundary_100",    1,  2,  100,     1,      2,      0,       0,      0 },
    { "zero_stats",      0,  0,   0,      1,      0,      0,      -1,      0 },
    { "convert_fail",    0,  0,   5,      0,      0,      0,      -1,      0 },
    { "vap_not_found",   0,  0,   5,      1,     -1,      0,      -1,      0 },
    { "overflow_200",    0,  0,  200,     1,      0,      0,       0,      1 },  /* OOB write */
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_assoc_client_response_input(const em_acr_test_case_t *tc)
{
    memset(client_assoc_stats, 0, sizeof(client_assoc_stats));
    memset(acr_mgr_buf, 0, sizeof(acr_mgr_buf));
    memset(acr_resp_buf, 0, sizeof(acr_resp_buf));

    if (tc->req_mask_set && tc->radio_index < MAX_NUM_RADIOS)
        client_assoc_stats[tc->radio_index].req_stats_vap_mask = (1u << tc->vap_index);

    if (acr_stat_pointer) { free(acr_stat_pointer); acr_stat_pointer = NULL; }
    int n = tc->stat_array_size > 0 ? tc->stat_array_size : 1;
    acr_stat_pointer = calloc((size_t)n, sizeof(sta_data_t));   /* valid source of n entries */

    wifi_provider_response_t *resp = (wifi_provider_response_t *)acr_resp_buf;
    resp->args.radio_index = tc->radio_index;
    resp->args.vap_index   = tc->vap_index;
    resp->args.app_info    = 0;
    resp->stat_array_size  = tc->stat_array_size;
    resp->stat_pointer     = acr_stat_pointer;

    acr_convert_name_ok = tc->convert_name_ok;
    acr_vap_array_index = tc->vap_array_index;
    acr_ready_calls = 0;
}

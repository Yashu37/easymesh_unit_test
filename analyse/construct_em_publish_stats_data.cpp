/*
 * TEST CASES / CONSTRUCTOR: construct_em_publish_stats_data
 *
 * scan_response (input) lives at eps_scanresp_buf; the wifi_ctrl stand-in at
 * eps_ctrl_buf. eps_encode_fail / eps_publish_fail steer the stubbed
 * webconfig_encode / bus_event_publish_fn outcomes.
 *
 * Cases: success (encode + publish OK -> RETURN_OK, eventName published),
 * encode_fail (-> RETURN_ERR), publish_fail (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char eps_ctrl_buf[sizeof(wifi_ctrl_t) + EPS_PAD];
alignas(16) char eps_scanresp_buf[sizeof(channel_scan_response_t) + EPS_PAD];
int  eps_encode_fail, eps_publish_fail;
char eps_published_event[256];
int  eps_publish_calls;

em_eps_test_case_t em_publish_stats_data_suite[] = {
    /* name           encode_fail publish_fail want_ret */
    { "success",        0,         0,          0 },
    { "encode_fail",    1,         0,         -1 },
    { "publish_fail",   0,         1,         -1 },
    { NULL, 0, 0, 0 }  /* sentinel */
};

void construct_em_publish_stats_data_input(const em_eps_test_case_t *tc)
{
    memset(eps_ctrl_buf, 0, sizeof(eps_ctrl_buf));
    memset(eps_scanresp_buf, 0, sizeof(eps_scanresp_buf));

    /* a minimal scan_response to copy */
    channel_scan_response_t *sr = (channel_scan_response_t *)eps_scanresp_buf;
    sr->num_results = 1;
    sr->results[0].operating_class = 115;
    sr->results[0].channel = 36;

    eps_encode_fail = tc->encode_fail;
    eps_publish_fail = tc->publish_fail;
    eps_published_event[0] = 0;
    eps_publish_calls = 0;
}

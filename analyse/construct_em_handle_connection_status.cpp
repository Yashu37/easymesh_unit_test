/*
 * TEST CASES / CONSTRUCTOR: construct_em_handle_connection_status
 *
 * conn_status (em_connection_status_event_t) lives at ehcs_conn_buf; the app
 * (with ctrl->handle) at ehcs_app_buf/ehcs_appctrl_buf. The runner poisons past
 * the conn struct. ehcs_publish_fail steers the stubbed publish.
 *
 * Cases: success (publish OK -> RETURN_OK), null_app, null_conn (-> RETURN_ERR),
 * publish_fail (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char ehcs_conn_buf[sizeof(em_connection_status_event_t) + EHCS_PAD];
alignas(16) char ehcs_app_buf[2048];
alignas(16) char ehcs_appctrl_buf[512];
int  ehcs_publish_fail, ehcs_publish_calls, ehcs_last_len;
char ehcs_published_event[128];

em_ehcs_test_case_t em_handle_connection_status_suite[] = {
    /* name          app_null conn_null publish_fail want_ret */
    { "success",       0,      0,        0,          0 },
    { "null_app",      1,      0,        0,         -1 },
    { "null_conn",     0,      1,        0,         -1 },
    { "publish_fail",  0,      0,        1,         -1 },
    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_handle_connection_status_input(const em_ehcs_test_case_t *tc)
{
    memset(ehcs_conn_buf, 0, sizeof(ehcs_conn_buf));
    memset(ehcs_app_buf, 0, sizeof(ehcs_app_buf));
    memset(ehcs_appctrl_buf, 0, sizeof(ehcs_appctrl_buf));

    em_connection_status_event_t *cs = (em_connection_status_event_t *)ehcs_conn_buf;
    unsigned char sm[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    unsigned char bs[6] = {0x40,0x41,0x42,0x43,0x44,0x45};
    memcpy(cs->sta_mac, sm, 6);
    memcpy(cs->bssid, bs, 6);
    cs->status_code = 0;
    cs->reason_code_present = 1;
    cs->reason_code = 7;

    wifi_app_t *app = (wifi_app_t *)ehcs_app_buf;
    app->ctrl = (decltype(app->ctrl))ehcs_appctrl_buf;

    ehcs_publish_fail = tc->publish_fail;
    ehcs_publish_calls = 0;
    ehcs_last_len = 0;
    ehcs_published_event[0] = 0;
}

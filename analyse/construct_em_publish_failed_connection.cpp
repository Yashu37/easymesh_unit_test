/*
 * TEST CASES / CONSTRUCTOR: construct_em_publish_failed_connection
 *
 * fc (input) lives at pfc_fc_buf; the wifi_ctrl stand-in at pfc_ctrl_buf. The
 * runner poisons past both. pfc_publish_fail steers the stubbed publish.
 *
 * Cases: success (publish OK -> RETURN_OK, JSON built), publish_fail (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char pfc_ctrl_buf[sizeof(wifi_ctrl_t) + PFC_PAD];
alignas(16) char pfc_fc_buf[sizeof(wifi_em_failed_conn_t) + PFC_PAD];
int  pfc_publish_fail, pfc_publish_calls;
char pfc_published_json[256];
char pfc_published_event[128];

em_pfc_test_case_t em_publish_failed_connection_suite[] = {
    /* name          publish_fail want_ret */
    { "success",       0,          0 },
    { "publish_fail",  1,         -1 },
    { NULL, 0, 0 }  /* sentinel */
};

void construct_em_publish_failed_connection_input(const em_pfc_test_case_t *tc)
{
    memset(pfc_ctrl_buf, 0, sizeof(pfc_ctrl_buf));
    memset(pfc_fc_buf, 0, sizeof(pfc_fc_buf));

    wifi_em_failed_conn_t *fc = (wifi_em_failed_conn_t *)pfc_fc_buf;
    unsigned char b[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    unsigned char s[6] = {0x20,0x21,0x22,0x23,0x24,0x25};
    memcpy(fc->bssid, b, 6);
    memcpy(fc->sta_mac, s, 6);
    fc->status = 1;
    fc->reason = 7;

    pfc_publish_fail = tc->publish_fail;
    pfc_publish_calls = 0;
    pfc_published_json[0] = 0;
    pfc_published_event[0] = 0;
}

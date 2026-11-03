/*
 * TEST CASES / CONSTRUCTOR: construct_em_handle_failed_connection
 *
 * arg (a sta_fail_data_t) lives at hfc_arg_buf; the runner poisons past the
 * struct. hfc_vap_null / hfc_publish_fail steer the stubbed getVapInfo /
 * em_publish_failed_connection.
 *
 * Cases: success (vap + publish OK -> RETURN_OK), null_arg (-> RETURN_ERR),
 * vap_null (getVapInfo NULL -> RETURN_ERR), publish_fail (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char hfc_arg_buf[sizeof(sta_fail_data_t) + HFC_PAD];
int hfc_vap_null, hfc_publish_fail, hfc_publish_calls;

em_hfc_test_case_t em_handle_failed_connection_suite[] = {
    /* name          arg_null vap_null publish_fail want_ret */
    { "success",       0,      0,       0,          0 },
    { "null_arg",      1,      0,       0,         -1 },
    { "vap_null",      0,      1,       0,         -1 },
    { "publish_fail",  0,      0,       1,         -1 },
    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_handle_failed_connection_input(const em_hfc_test_case_t *tc)
{
    memset(hfc_arg_buf, 0, sizeof(hfc_arg_buf));
    sta_fail_data_t *sd = (sta_fail_data_t *)hfc_arg_buf;
    sd->ap_index = 2;
    unsigned char s[6] = {0x20,0x21,0x22,0x23,0x24,0x25};
    memcpy(sd->sta_mac, s, 6);
    sd->status = 1;
    sd->reason = 7;

    hfc_vap_null     = tc->vap_null;
    hfc_publish_fail = tc->publish_fail;
    hfc_publish_calls = 0;
}

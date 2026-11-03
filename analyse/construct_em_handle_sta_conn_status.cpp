/*
 * TEST CASES / CONSTRUCTOR: construct_em_handle_sta_conn_status
 *
 * sta_data (rdk_sta_data_t) lives at hscs_data_buf; the wifi_ctrl stand-in at
 * hscs_ctrl_buf. The runner poisons past both.
 *
 * Cases: success (publishes WIFI_EM_ASSOCIATION_STATUS with the sta_data
 * payload), null_data (-> RETURN_ERR).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char hscs_ctrl_buf[sizeof(wifi_ctrl_t) + HSCS_PAD];
alignas(16) char hscs_data_buf[sizeof(rdk_sta_data_t) + HSCS_PAD];
int  hscs_publish_calls, hscs_last_len;
char hscs_published_event[128];

em_hscs_test_case_t em_handle_sta_conn_status_suite[] = {
    /* name        data_null want_ret(only checked for null_data) */
    { "success",     0,       0 },
    { "null_data",   1,      -1 },
    { NULL, 0, 0 }  /* sentinel */
};

void construct_em_handle_sta_conn_status_input(const em_hscs_test_case_t *tc)
{
    memset(hscs_ctrl_buf, 0, sizeof(hscs_ctrl_buf));
    memset(hscs_data_buf, 0, sizeof(hscs_data_buf));

    rdk_sta_data_t *sd = (rdk_sta_data_t *)hscs_data_buf;
    sd->stats.connect_status = 2; /* connected */
    sd->stats.vap_index = 1;
    unsigned char b[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    memcpy(sd->bss_info.bssid, b, 6);
    (void)tc;

    hscs_publish_calls = 0;
    hscs_last_len = 0;
    hscs_published_event[0] = 0;
}

/*
 * TEST CASES / CONSTRUCTOR: construct_webconfig_harvester_apply
 * The decoded webconfig struct lives at the start of wha_wd_buf (WHA_PAD tail,
 * poisoned by the runner; mac_address is the struct's last field, its bytes
 * past the NUL are poisoned too).
 * Cases: plain_mac (12 hex chars fit char[13]), short_mac, empty_mac.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char wha_wd_buf[sizeof(webconfig_subdoc_data_t) + WHA_PAD];
int wha_rep_calls, wha_def_calls, wha_ttl_calls, wha_mac_calls, wha_en_calls, wha_en_val;
unsigned char wha_en_mac[6];

harv_wha_test_case_t webconfig_harvester_apply_suite[] = {
    /* name        mac             enabled want_mac */
    { "plain_mac", "aabbccddeeff", 1, {0xaa,0xbb,0xcc,0xdd,0xee,0xff} },
    { "short_mac", "112233445566", 0, {0x11,0x22,0x33,0x44,0x55,0x66} },
    { "empty_mac", "",             1, {0xEE,0xEE,0xEE,0xEE,0xEE,0xEE} },
    { NULL, NULL, 0, {0} }  /* sentinel */
};

void construct_webconfig_harvester_apply_input(const harv_wha_test_case_t *tc)
{
    memset(wha_wd_buf, 0, sizeof(wha_wd_buf));
    wha_rep_calls = wha_def_calls = wha_ttl_calls = wha_mac_calls = wha_en_calls = wha_en_val = 0;
    memset(wha_en_mac, 0xEE, sizeof(wha_en_mac));   /* sta_mac stays 0xEE if the string is empty */

    webconfig_subdoc_data_t *wd = (webconfig_subdoc_data_t *)wha_wd_buf;
    wd->u.decoded.harvester.b_inst_client_enabled = tc->enabled ? true : false;
    wd->u.decoded.harvester.u_inst_client_reporting_period = 30;
    wd->u.decoded.harvester.u_inst_client_def_reporting_period = 300;
    wd->u.decoded.harvester.u_inst_client_def_override_ttl = 3600;
    snprintf(wd->u.decoded.harvester.mac_address, sizeof(wd->u.decoded.harvester.mac_address), "%s", tc->mac);
}

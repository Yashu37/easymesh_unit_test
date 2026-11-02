/*
 * TEST CASES / CONSTRUCTOR: construct_start_sta_channel_scan
 * mgr at ssc_mgr_buf (radio_interface_map[0] matches scan_req->ruid via the
 * fixed MAC); scan_req at ssc_req_buf. num_operating_classes=1, with the
 * class's operating_class == global_op_class. num_channels is the knob: a
 * safe value (<=64) vs an overflowing value (>64, no bound check -> channels[64]).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char ssc_mgr_buf[sizeof(wifi_mgr_t) + SSC_PAD];
char ssc_req_buf[sizeof(channel_scan_request_t) + SSC_PAD];
int  ssc_global_op_class;
int  ssc_scan_calls, ssc_scan_num;   /* set by handler stub (declared extern below) */

start_sta_channel_scan_test_case_t start_sta_channel_scan_suite[] = {
    /* name            match_class  num_channels  expect_overflow */
    { "safe_10ch",       1,          10,           0 },
    { "boundary_64ch",   1,          64,           0 },
    { "overflow_70ch",   1,          70,           1 },   /* num_channels > 64 -> channels[64] OOB write */
    { NULL, 0, 0, 0 }
};

void construct_start_sta_channel_scan_input(const start_sta_channel_scan_test_case_t *tc)
{
    memset(ssc_mgr_buf, 0, sizeof(ssc_mgr_buf));
    memset(ssc_req_buf, 0, sizeof(ssc_req_buf));
    wifi_mgr_t *mgr = (wifi_mgr_t *)ssc_mgr_buf;
    snprintf(mgr->hal_cap.wifi_prop.radio_interface_map[0].interface_name, 32, "wlan0");
    mgr->hal_cap.wifi_prop.radio_interface_map[0].radio_index = 0;
    mgr->radio_config[0].oper.countryCode = 1;
    mgr->radio_config[0].oper.operatingClass = 115;

    channel_scan_request_t *req = (channel_scan_request_t *)ssc_req_buf;
    unsigned char mac[6] = {0x10,0x11,0x12,0x13,0x14,0x15};   /* matches mac_address_from_name */
    memcpy(req->ruid, mac, 6);
    req->num_operating_classes = 1;
    ssc_global_op_class = 115;
    req->operating_classes[0].operating_class = tc->match_class ? 115 : 200;
    req->operating_classes[0].num_channels = tc->num_channels;   /* UNVALIDATED */
    for (unsigned int j = 0; j < tc->num_channels && j < EM_MAX_CHANNELS; j++)
        req->operating_classes[0].channels[j] = (unsigned char)(36 + j);

    ssc_scan_calls = 0; ssc_scan_num = 0;
}

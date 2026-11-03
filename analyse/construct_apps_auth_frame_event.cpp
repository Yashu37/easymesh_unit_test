/*
 * TEST CASES / CONSTRUCTOR: construct_apps_auth_frame_event
 * Caller-owned buffers: aaf_app_buf (struct wifi_app) and aaf_msg_buf
 * (frame_data_t); the runner poisons the AAF_PAD tail of both.
 * Cases span the ap_index range so the formatted namespace goes from 1 digit
 * up to the longest possible value (INT_MIN+1 -> "-2147483647").
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

alignas(16) char aaf_app_buf[sizeof(struct wifi_app) + AAF_PAD];
alignas(16) char aaf_msg_buf[sizeof(frame_data_t) + AAF_PAD];
char aaf_sent_ns[256];
int  aaf_send_calls;

lv_aaf_test_case_t apps_auth_frame_event_suite[] = {
    /* name           ap_index   want_ns */
    { "ap_zero",      0,         "Device.WiFi.Events.VAP.1.Frames.Mgmt" },
    { "ap_fifteen",   15,        "Device.WiFi.Events.VAP.16.Frames.Mgmt" },
    { "ap_negative",  -5,        "Device.WiFi.Events.VAP.-4.Frames.Mgmt" },
    { "ap_big",       2147483646,"Device.WiFi.Events.VAP.2147483647.Frames.Mgmt" },
    { "ap_int_min",   INT_MIN,   "Device.WiFi.Events.VAP.-2147483647.Frames.Mgmt" },
    { NULL, 0, NULL }  /* sentinel */
};

void construct_apps_auth_frame_event_input(const lv_aaf_test_case_t *tc)
{
    memset(aaf_app_buf, 0, sizeof(aaf_app_buf));
    memset(aaf_msg_buf, 0, sizeof(aaf_msg_buf));
    memset(aaf_sent_ns, 0, sizeof(aaf_sent_ns));
    aaf_send_calls = 0;
    ((frame_data_t *)aaf_msg_buf)->frame.ap_index = tc->ap_index;
}

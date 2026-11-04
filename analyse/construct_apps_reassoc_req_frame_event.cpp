/*
 * TEST CASES / CONSTRUCTOR: construct_apps_reassoc_req_frame_event
 * Caller-owned buffers: arf_app_buf (struct wifi_app) and arf_msg_buf
 * (frame_data_t); the runner poisons the ARF_PAD tail of both.
 * Cases span the ap_index range up to the longest formatted namespace
 * (INT_MIN+1 -> "-2147483647", 46 bytes).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "common.h"

alignas(16) char arf_app_buf[sizeof(struct wifi_app) + ARF_PAD];
alignas(16) char arf_msg_buf[sizeof(frame_data_t) + ARF_PAD];
char arf_sent_ns[256];
int  arf_send_calls;

lv_arf_test_case_t apps_reassoc_req_frame_event_suite[] = {
    /* name           ap_index   want_ns */
    { "ap_zero",      0,         "Device.WiFi.Events.VAP.1.Frames.Mgmt" },
    { "ap_fifteen",   15,        "Device.WiFi.Events.VAP.16.Frames.Mgmt" },
    { "ap_negative",  -5,        "Device.WiFi.Events.VAP.-4.Frames.Mgmt" },
    { "ap_big",       2147483646,"Device.WiFi.Events.VAP.2147483647.Frames.Mgmt" },
    { "ap_int_min",   INT_MIN,   "Device.WiFi.Events.VAP.-2147483647.Frames.Mgmt" },
    { NULL, 0, NULL }  /* sentinel */
};

void construct_apps_reassoc_req_frame_event_input(const lv_arf_test_case_t *tc)
{
    memset(arf_app_buf, 0, sizeof(arf_app_buf));
    memset(arf_msg_buf, 0, sizeof(arf_msg_buf));
    memset(arf_sent_ns, 0, sizeof(arf_sent_ns));
    arf_send_calls = 0;
    ((frame_data_t *)arf_msg_buf)->frame.ap_index = tc->ap_index;
}

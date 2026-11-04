/*
 * TEST CASES / CONSTRUCTOR: construct_radio_temperature_response
 * Caller-owned buffers: lrt_ctrl_buf (wifi_ctrl_t), lrt_app_buf (levl
 * wifi_app), lrt_resp_buf (wifi_provider_response_t) and lrt_stat_buf (ONE
 * radio_data_t, pointed to by stat_pointer even when stat_array_size is 3 --
 * the handler never advances the pointer, so no read past element 0); the
 * runner poisons the LRT_PAD tail of each.
 *
 * Cases: null_ctrl, null_app, size_zero (no publish), size_one, size_three
 * (same element published 3 times), radio_5 (-> Radio.6), radio_max
 * (radio_index+1 wraps to 0 -> Radio.0, still bounded), publish_fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lrt_ctrl_buf[sizeof(wifi_ctrl_t) + LRT_PAD];
alignas(16) char lrt_app_buf[sizeof(struct wifi_app) + LRT_PAD];
alignas(16) char lrt_resp_buf[sizeof(wifi_provider_response_t) + LRT_PAD];
alignas(16) char lrt_stat_buf[sizeof(radio_data_t) + LRT_PAD];
int lrt_null_ctrl, lrt_null_app, lrt_publish_fail;
int lrt_pub_calls, lrt_pub_type;
unsigned int lrt_pub_value;
char lrt_pub_name[128];

lv_lrt_test_case_t radio_temperature_response_suite[] = {
    /* name            nc na  radio    n  temp pf | ret pub name */
    { "null_ctrl",      1, 0,   0,      1,  50, 0,   1, 0, "" },
    { "null_app",       0, 1,   0,      1,  50, 0,  -1, 0, "" },
    { "size_zero",      0, 0,   0,      0,  50, 0,   0, 0, "" },
    { "size_one",       0, 0,   0,      1,  50, 0,   0, 1, "Device.WiFi.Events.Radio.1.Temperature" },
    { "size_three",     0, 0,   2,      3,  61, 0,   0, 3, "Device.WiFi.Events.Radio.3.Temperature" },
    { "radio_5",        0, 0,   5,      1,  77, 0,   0, 1, "Device.WiFi.Events.Radio.6.Temperature" },
    { "radio_max",      0, 0, 0xFFFFFFFFu, 1, 80, 0, 0, 1, "Device.WiFi.Events.Radio.0.Temperature" },
    { "publish_fail",   0, 0,   0,      3,  50, 1,  -1, 1, "Device.WiFi.Events.Radio.1.Temperature" },
    { NULL, 0,0,0,0,0,0,0,0, NULL }  /* sentinel */
};

void construct_radio_temperature_response_input(const lv_lrt_test_case_t *tc)
{
    memset(lrt_ctrl_buf, 0, sizeof(lrt_ctrl_buf));
    memset(lrt_app_buf, 0, sizeof(lrt_app_buf));
    memset(lrt_resp_buf, 0, sizeof(lrt_resp_buf));
    memset(lrt_stat_buf, 0, sizeof(lrt_stat_buf));
    lrt_null_ctrl = tc->null_ctrl; lrt_null_app = tc->null_app; lrt_publish_fail = tc->pub_fail;
    lrt_pub_calls = 0; lrt_pub_value = 0; lrt_pub_type = -1; lrt_pub_name[0] = 0;

    ((radio_data_t *)lrt_stat_buf)->radio_Temperature = tc->temp;
    wifi_provider_response_t *r = (wifi_provider_response_t *)lrt_resp_buf;
    r->stat_pointer = lrt_stat_buf;
    r->stat_array_size = tc->n;
    r->args.radio_index = tc->radio_index;
}

/*
 * TEST CASES / CONSTRUCTOR: construct_levl_event_webconfig_set_data
 * Caller-owned buffers: lse_apps_buf (levl wifi_app) and lse_doc_buf
 * (webconfig_subdoc_data_t whose levl config is read); the runner poisons the
 * LSE_PAD tail of both.
 * Cases: other_type (no-op), max_zero (-> 5), max_set, changed duration /
 * interval, unchanged values, mac set + client connected (schedule), mac set
 * + not connected (no schedule), mac null (no lookup).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lse_apps_buf[sizeof(struct wifi_app) + LSE_PAD];
alignas(16) char lse_doc_buf[sizeof(webconfig_subdoc_data_t) + LSE_PAD];
int lse_ap_ret, lse_sched_calls, lse_sched_ap, lse_sched_dur, lse_sched_int;
unsigned char lse_sched_mac[6];

lv_lse_test_case_t levl_event_webconfig_set_data_suite[] = {
    /* name              levl max dur int mac ap  idur iint | wmax wdur wint wsched */
    { "other_type",        0,  9, 30, 40, 1,  2,   1,   1,     0,   1,   1,   0 },
    { "max_zero",          1,  0, 30, 40, 0,  0,   1,   1,     5,  30,  40,   0 },
    { "max_set",           1,  9, 30, 40, 0,  0,   1,   1,     9,  30,  40,   0 },
    { "values_unchanged",  1,  3, 30, 40, 0,  0,  30,  40,     3,  30,  40,   0 },
    { "mac_connected",     1,  3, 30, 40, 1,  2,   1,   1,     3,  30,  40,   1 },
    { "mac_not_connected", 1,  3, 30, 40, 1, -1,   1,   1,     3,  30,  40,   0 },
    { "mac_null",          1,  3, 30, 40, 0,  2,   1,   1,     3,  30,  40,   0 },
    { NULL, 0,0,0,0,0,0,0,0,0,0,0,0 }  /* sentinel */
};

void construct_levl_event_webconfig_set_data_input(const lv_lse_test_case_t *tc)
{
    memset(lse_apps_buf, 0, sizeof(lse_apps_buf));
    memset(lse_doc_buf, 0, sizeof(lse_doc_buf));
    lse_ap_ret = tc->ap_ret;
    lse_sched_calls = 0; lse_sched_ap = -9; lse_sched_dur = lse_sched_int = -9;
    memset(lse_sched_mac, 0, 6);

    struct wifi_app *app = (struct wifi_app *)lse_apps_buf;
    pthread_mutex_init(&app->data.u.levl.lock, NULL);
    app->data.u.levl.sounding_duration = tc->init_dur;
    app->data.u.levl.publish_interval = tc->init_int;

    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)lse_doc_buf;
    doc->type = tc->type_levl ? 5 : 0;
    levl_config_t *c = &doc->u.decoded.levl;
    c->max_num_csi_clients = tc->max_clients;
    c->levl_sounding_duration = tc->dur;
    c->levl_publish_interval = tc->interval;
    if (tc->mac_set) { unsigned char m[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01}; memcpy(c->clientMac, m, 6); }
}

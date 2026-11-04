/*
 * TEST CASES / CONSTRUCTOR: construct_levl_disassoc_device_event
 * Caller-owned buffers: lds_ctrl_buf (wifi_ctrl_t), lds_app_buf (levl
 * wifi_app), lds_csi_buf (csi wifi_app, also the pending-map token),
 * lds_data_buf (assoc_dev_data_t); the runner poisons the LDS_PAD tail of each.
 * The entries for AA:BB:CC:DD:EE:01 (ap 3) are heap blocks present per case.
 *
 * Cases: found_both (stop+publish+cancel, pending freed), found_curr_noid
 * (sched id 0: no cancel), only_pending, none_found, counter_zero (stays 0),
 * null_data, null_app, null_csi_app, null_curr_map, null_pend_map.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lds_ctrl_buf[sizeof(wifi_ctrl_t) + LDS_PAD];
alignas(16) char lds_app_buf[sizeof(struct wifi_app) + LDS_PAD];
alignas(16) char lds_csi_buf[sizeof(struct wifi_app) + LDS_PAD];
alignas(16) char lds_data_buf[sizeof(assoc_dev_data_t) + LDS_PAD];
int lds_null_app;
int lds_pub_calls, lds_pub_status, lds_stop_calls, lds_stop_ap, lds_cancel_calls, lds_cancel_id, lds_freearg_calls;
unsigned char lds_pub_mac[6], lds_stop_mac[6];

static void lds_stop_stub(wifi_app_t *app, int ap, unsigned char *mac, int inst)
{
    (void)app; (void)inst;
    lds_stop_calls++; lds_stop_ap = ap; memcpy(lds_stop_mac, mac, 6);
}

lv_lds_test_case_t levl_disassoc_device_event_suite[] = {
    /* name              nd na ncsi ncm npm curr sid pend nsnd | stop pub cancel freearg nsnd_after cur_left pend_left */
    { "found_both",       0, 0, 0,  0,  0,  1,  7,  1,  2,       1,  1,  1,     1,      1,         0,       0 },
    { "found_curr_noid",  0, 0, 0,  0,  0,  1,  0,  0,  1,       1,  1,  0,     0,      0,         0,       0 },
    { "only_pending",     0, 0, 0,  0,  0,  0,  0,  1,  1,       0,  0,  0,     0,      0,         0,       0 },
    { "none_found",       0, 0, 0,  0,  0,  0,  0,  0,  3,       0,  0,  0,     0,      2,         0,       0 },
    { "counter_zero",     0, 0, 0,  0,  0,  1,  7,  0,  0,       1,  1,  1,     1,      0,         0,       0 },
    { "null_data",        1, 0, 0,  0,  0,  1,  7,  1,  2,       0,  0,  0,     0,      2,         1,       1 },
    { "null_app",         0, 1, 0,  0,  0,  1,  7,  1,  2,       0,  0,  0,     0,      2,         1,       1 },
    { "null_csi_app",     0, 0, 1,  0,  0,  1,  7,  1,  2,       0,  0,  0,     0,      2,         1,       1 },
    { "null_curr_map",    0, 0, 0,  1,  0,  1,  7,  1,  2,       0,  0,  0,     0,      2,         1,       1 },
    { "null_pend_map",    0, 0, 0,  0,  1,  1,  7,  1,  2,       0,  0,  0,     0,      2,         1,       1 },
    { NULL, 0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0 }  /* sentinel */
};

void construct_levl_disassoc_device_event_input(const lv_lds_test_case_t *tc)
{
    memset(lds_ctrl_buf, 0, sizeof(lds_ctrl_buf));
    memset(lds_app_buf, 0, sizeof(lds_app_buf));
    memset(lds_csi_buf, 0, sizeof(lds_csi_buf));
    memset(lds_data_buf, 0, sizeof(lds_data_buf));
    lds_null_app = tc->null_app;
    lds_pub_calls = lds_stop_calls = lds_cancel_calls = lds_freearg_calls = 0;
    lds_pub_status = -1; lds_stop_ap = -1; lds_cancel_id = -1;
    memset(lds_pub_mac, 0, 6); memset(lds_stop_mac, 0, 6);

    struct wifi_app *app = (struct wifi_app *)lds_app_buf;
    struct wifi_app *csi = (struct wifi_app *)lds_csi_buf;
    pthread_mutex_init(&app->data.u.levl.lock, NULL);
    app->data.u.levl.csi_app = tc->null_csi ? NULL : (wifi_app_t *)csi;
    app->data.u.levl.curr_sounding_mac_map = tc->null_curr_map ? NULL : (void *)lds_app_buf;   /* non-NULL token */
    app->data.u.levl.pending_mac_map = tc->null_pend_map ? NULL : (void *)lds_csi_buf;         /* non-NULL token */
    app->data.u.levl.num_current_sounding = tc->num_sounding;
    csi->data.u.csi.csi_fns.csi_stop_fn = lds_stop_stub;

    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    lds_set_slots(mac, tc->curr, tc->sched_id, tc->pend);

    assoc_dev_data_t *d = (assoc_dev_data_t *)lds_data_buf;
    d->ap_index = 3;
    memcpy(d->dev_stats.cli_MACAddress, mac, 6);
}

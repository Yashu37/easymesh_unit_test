/*
 * TEST CASES / CONSTRUCTOR: construct_process_levl_sounding_timeout
 * Caller-owned buffers: lst_ctrl_buf (wifi_ctrl_t), lst_app_buf (levl wifi_app),
 * lst_csi_buf (csi wifi_app); the runner poisons the LST_PAD tail of each.
 * t_data is a heap timeout_data_t (freed by the handler on every path).
 * The sounding entry for AA:BB:CC:DD:EE:01 (ap 3) is present only when slot=1.
 *
 * Cases: found (stop + publish + schedule), not_found (schedule only),
 * null_tdata, null_ctrl, null_app, null_csi_app, null_map.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lst_ctrl_buf[sizeof(wifi_ctrl_t) + LST_PAD];
alignas(16) char lst_app_buf[sizeof(struct wifi_app) + LST_PAD];
alignas(16) char lst_csi_buf[sizeof(struct wifi_app) + LST_PAD];
timeout_data_t *lst_tdata;
int lst_null_ctrl, lst_null_app;
int lst_pub_calls, lst_pub_status, lst_sched_calls, lst_stop_calls, lst_stop_ap;
unsigned char lst_pub_mac[6], lst_stop_mac[6];

static void lst_stop_stub(wifi_app_t *app, int ap, unsigned char *mac, int inst)
{
    (void)app; (void)inst;
    lst_stop_calls++; lst_stop_ap = ap; memcpy(lst_stop_mac, mac, 6);
}

lv_lst_test_case_t process_levl_sounding_timeout_suite[] = {
    /* name          nt nc na ncsi nm slot ret stop pub sched */
    { "found",        0, 0, 0, 0,  0, 1,   0,  1,   1,  1 },
    { "not_found",    0, 0, 0, 0,  0, 0,   0,  0,   0,  1 },
    { "null_tdata",   1, 0, 0, 0,  0, 0,  -1,  0,   0,  0 },
    { "null_ctrl",    0, 1, 0, 0,  0, 0,  -1,  0,   0,  0 },
    { "null_app",     0, 0, 1, 0,  0, 0,  -1,  0,   0,  0 },
    { "null_csi_app", 0, 0, 0, 1,  0, 0,  -1,  0,   0,  0 },
    { "null_map",     0, 0, 0, 0,  1, 0,  -1,  0,   0,  0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_process_levl_sounding_timeout_input(const lv_lst_test_case_t *tc)
{
    memset(lst_ctrl_buf, 0, sizeof(lst_ctrl_buf));
    memset(lst_app_buf, 0, sizeof(lst_app_buf));
    memset(lst_csi_buf, 0, sizeof(lst_csi_buf));
    lst_null_ctrl = tc->null_ctrl;
    lst_null_app = tc->null_app;
    lst_pub_calls = lst_sched_calls = lst_stop_calls = 0;
    lst_pub_status = -1; lst_stop_ap = -1;
    memset(lst_pub_mac, 0, 6); memset(lst_stop_mac, 0, 6);

    struct wifi_app *app = (struct wifi_app *)lst_app_buf;
    struct wifi_app *csi = (struct wifi_app *)lst_csi_buf;
    pthread_mutex_init(&app->data.u.levl.lock, NULL);
    app->data.u.levl.csi_app = tc->null_csi ? NULL : (wifi_app_t *)csi;
    app->data.u.levl.curr_sounding_mac_map = tc->null_map ? NULL : (void *)lst_app_buf;   /* non-NULL token */
    csi->data.u.csi.csi_fns.csi_stop_fn = lst_stop_stub;

    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    lst_set_slot(tc->slot ? mac : NULL, 3);

    lst_tdata = NULL;
    if (!tc->null_tdata) {
        lst_tdata = (timeout_data_t *)calloc(1, sizeof(timeout_data_t));
        memcpy(lst_tdata->mac_addr, mac, 6);
        lst_tdata->ap_index = 3;
    }
}

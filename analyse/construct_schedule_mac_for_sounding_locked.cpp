/*
 * TEST CASES / CONSTRUCTOR: construct_schedule_mac_for_sounding_locked
 * Caller-owned buffers: lsm_mac_buf (the 6-byte mac_address argument),
 * lsm_ctrl_buf (wifi_ctrl_t), lsm_app_buf (levl wifi_app) and lsm_csi_buf (csi
 * wifi_app); the runner poisons the LSM_PAD tail of each.
 * Stubs record: map puts (current / pending), csi start/stop calls, publishes,
 * scheduler calls. Objects the handler hands over (sounding entry, timeout
 * data) are tracked in lsm_owned[] and freed by lsm_cleanup().
 *
 * Cases: null_app, not_subscribed, null_csi_app, null_map, dup_mac, paused,
 * start_ok, start_fail (-> pending + postpone timer), sched_fail (csi stopped,
 * publish 1 then 0), full (pending).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

unsigned char lsm_mac_buf[6 + LSM_PAD];
alignas(16) char lsm_ctrl_buf[sizeof(wifi_ctrl_t) + LSM_PAD];
alignas(16) char lsm_app_buf[sizeof(struct wifi_app) + LSM_PAD];
alignas(16) char lsm_csi_buf[sizeof(struct wifi_app) + LSM_PAD];
char lsm_curr_token, lsm_pend_token;
void *lsm_owned[8]; int lsm_n_owned;
void *lsm_last_tdata_expect;
char lsm_last_key[64];
int lsm_null_app, lsm_dup, lsm_curr_count, lsm_curr_put, lsm_pend_put, lsm_sched_calls, lsm_sched_ret;
int lsm_pub_calls, lsm_pub_status[4], lsm_start_calls, lsm_stop_calls, lsm_start_ret;

static int lsm_start_stub(wifi_app_t *a, int ap, unsigned char *mac, int inst) { (void)a; (void)ap; (void)mac; (void)inst; lsm_start_calls++; return lsm_start_ret; }
static void lsm_stop_stub(wifi_app_t *a, int ap, unsigned char *mac, int inst) { (void)a; (void)ap; (void)mac; (void)inst; lsm_stop_calls++; }

lv_lsm_test_case_t schedule_mac_for_sounding_locked_suite[] = {
    /* name           nullapp subs nullcsi nullmap dup paused cnt max startret schedret | ret curr pend start stop pub sched */
    { "null_app",       1, 1, 0, 0, 0, 0, 0, 2,  0,  0,    -1, 0, 0, 0, 0, 0, 0 },
    { "not_subscribed", 0, 0, 0, 0, 0, 0, 0, 2,  0,  0,     0, 0, 0, 0, 0, 0, 0 },
    { "null_csi_app",   0, 1, 1, 0, 0, 0, 0, 2,  0,  0,    -1, 0, 0, 0, 0, 0, 0 },
    { "null_map",       0, 1, 0, 1, 0, 0, 0, 2,  0,  0,    -1, 0, 0, 0, 0, 0, 0 },
    { "dup_mac",        0, 1, 0, 0, 1, 0, 0, 2,  0,  0,    -1, 0, 0, 0, 0, 0, 0 },
    { "paused",         0, 1, 0, 0, 0, 1, 0, 2,  0,  0,     0, 0, 1, 0, 0, 0, 0 },
    { "start_ok",       0, 1, 0, 0, 0, 0, 0, 2,  0,  0,     0, 1, 0, 1, 0, 1, 1 },
    { "start_fail",     0, 1, 0, 0, 0, 0, 0, 2, -1,  0,     0, 0, 1, 1, 0, 0, 1 },
    { "sched_fail",     0, 1, 0, 0, 0, 0, 0, 2,  0, -1,    -1, 0, 0, 1, 1, 2, 1 },
    { "full",           0, 1, 0, 0, 0, 0, 2, 2,  0,  0,     0, 0, 1, 0, 0, 0, 0 },
    { NULL, 0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0 }  /* sentinel */
};

void lsm_cleanup(void)
{
    for (int i = 0; i < lsm_n_owned; i++) free(lsm_owned[i]);
    lsm_n_owned = 0;
}

void construct_schedule_mac_for_sounding_locked_input(const lv_lsm_test_case_t *tc)
{
    lsm_cleanup();
    memset(lsm_ctrl_buf, 0, sizeof(lsm_ctrl_buf));
    memset(lsm_app_buf, 0, sizeof(lsm_app_buf));
    memset(lsm_csi_buf, 0, sizeof(lsm_csi_buf));
    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    memset(lsm_mac_buf, 0, sizeof(lsm_mac_buf));
    memcpy(lsm_mac_buf, mac, 6);

    lsm_null_app = tc->null_app; lsm_dup = tc->dup;
    lsm_curr_count = tc->curr_count; lsm_sched_ret = tc->sched_ret; lsm_start_ret = tc->start_ret;
    lsm_curr_put = lsm_pend_put = lsm_sched_calls = lsm_pub_calls = lsm_start_calls = lsm_stop_calls = 0;
    memset(lsm_pub_status, -1, sizeof(lsm_pub_status));
    lsm_last_tdata_expect = NULL; lsm_last_key[0] = 0;

    struct wifi_app *app = (struct wifi_app *)lsm_app_buf;
    struct wifi_app *csi = (struct wifi_app *)lsm_csi_buf;
    app->data.u.levl.csi_event_subscribed = tc->subscribed ? true : false;
    app->data.u.levl.csi_app = tc->null_csi ? NULL : (wifi_app_t *)csi;
    app->data.u.levl.curr_sounding_mac_map = tc->null_map ? NULL : (void *)&lsm_curr_token;
    app->data.u.levl.pending_mac_map = (void *)&lsm_pend_token;
    app->data.u.levl.paused = tc->paused;
    app->data.u.levl.max_num_csi_clients = tc->max_clients;
    csi->data.u.csi.csi_fns.csi_start_fn = lsm_start_stub;
    csi->data.u.csi.csi_fns.csi_stop_fn  = lsm_stop_stub;
}

/*
 * TEST CASES / CONSTRUCTOR: construct_process_csi_stop_levl_locked
 * Caller-owned buffers: lcs_ctrl_buf (wifi_ctrl_t), lcs_app_buf (levl
 * wifi_app), lcs_csi_buf (csi wifi_app); the runner poisons the LCS_PAD tail
 * of each. The sounding entries are heap blocks (n = 0..2).
 *
 * Cases: empty_map, one_with_id (cancel + stop + publish + move), one_no_id,
 * two_entries (iterator advances past removed entries), null_ctrl, null_app,
 * null_map.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lcs_ctrl_buf[sizeof(wifi_ctrl_t) + LCS_PAD];
alignas(16) char lcs_app_buf[sizeof(struct wifi_app) + LCS_PAD];
alignas(16) char lcs_csi_buf[sizeof(struct wifi_app) + LCS_PAD];
int lcs_null_ctrl;
int lcs_pub_calls, lcs_pub_status, lcs_stop_calls, lcs_cancel_calls, lcs_cancel_id, lcs_freearg_calls;

static void lcs_stop_stub(wifi_app_t *app, int ap, unsigned char *mac, int inst)
{
    (void)app; (void)ap; (void)mac; (void)inst;
    lcs_stop_calls++;
}

lv_lcs_test_case_t process_csi_stop_levl_locked_suite[] = {
    /* name          nc na nm  n sid | ret stop pub cancel curr pend */
    { "empty_map",    0, 0, 0, 0, 0,   0,   0,  0,   0,    0,  0 },
    { "one_with_id",  0, 0, 0, 1, 7,   0,   1,  1,   1,    0,  1 },
    { "one_no_id",    0, 0, 0, 1, 0,   0,   1,  1,   0,    0,  1 },
    { "two_entries",  0, 0, 0, 2, 7,   0,   2,  2,   2,    0,  2 },
    { "null_ctrl",    1, 0, 0, 1, 7,  -1,   0,  0,   0,    1,  0 },
    { "null_app",     0, 1, 0, 1, 7,  -1,   0,  0,   0,    1,  0 },
    { "null_map",     0, 0, 1, 1, 7,  -1,   0,  0,   0,    1,  0 },
    { NULL, 0,0,0,0,0, 0,0,0,0,0,0 }  /* sentinel */
};

void construct_process_csi_stop_levl_locked_input(const lv_lcs_test_case_t *tc)
{
    memset(lcs_ctrl_buf, 0, sizeof(lcs_ctrl_buf));
    memset(lcs_app_buf, 0, sizeof(lcs_app_buf));
    memset(lcs_csi_buf, 0, sizeof(lcs_csi_buf));
    lcs_null_ctrl = tc->null_ctrl;
    lcs_pub_calls = lcs_stop_calls = lcs_cancel_calls = lcs_freearg_calls = 0;
    lcs_pub_status = -1; lcs_cancel_id = -1;

    struct wifi_app *app = (struct wifi_app *)lcs_app_buf;
    struct wifi_app *csi = (struct wifi_app *)lcs_csi_buf;
    app->data.u.levl.csi_app = (wifi_app_t *)csi;
    app->data.u.levl.curr_sounding_mac_map = tc->null_map ? NULL : (void *)lcs_app_buf;   /* non-NULL token */
    app->data.u.levl.pending_mac_map = (void *)lcs_csi_buf;                               /* non-NULL token */
    csi->data.u.csi.csi_fns.csi_stop_fn = lcs_stop_stub;
    lcs_set_entries(tc->n, tc->sched_id);
}

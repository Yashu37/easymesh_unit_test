/*
 * TEST CASES / CONSTRUCTOR: construct_schedule_from_pending_map_locked
 * The wifi_app stand-in lives in lsp_app_buf (WIFI_PAD tail poisoned by the
 * runner). Pending entries are heap levl_sched_data_t (ASan redzones); the
 * handler frees the ones it removes, lsp_free_entries() frees any left over.
 * get_ap_index_from_clientmac returns (signed char)mac[5]: >=0x80 = "not connected".
 *
 * Cases: empty_map, connected, disconnected_then_connected, only_disconnected,
 * sounding_full (num_current >= max), null_app, null_map.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lsp_app_buf[sizeof(struct wifi_app) + LSP_PAD];
levl_sched_data_t *lsp_entries[8];
int lsp_n, lsp_sched_calls, lsp_sched_ap, lsp_sched_dur, lsp_sched_int;
unsigned char lsp_sched_mac[6];

lv_lsp_test_case_t schedule_from_pending_map_locked_suite[] = {
    /* name                         n  mac5            cur max null ret sched ap rem */
    { "empty_map",                  0, {0,0,0},         0, 4, 0,   0,  0,  -1, 0 },
    { "connected",                  1, {0x03,0,0},      0, 4, 0,   0,  1,   3, 0 },
    { "disconnected_then_connected",2, {0x90,0x05,0},   0, 4, 0,   0,  1,   5, 0 },
    { "only_disconnected",          2, {0x90,0x91,0},   0, 4, 0,   0,  0,  -1, 0 },
    { "sounding_full",              1, {0x03,0,0},      4, 4, 0,   0,  0,  -1, 1 },
    { "null_app",                   0, {0,0,0},         0, 4, 1,  -1,  0,  -1, 0 },
    { "null_map",                   1, {0x03,0,0},      0, 4, 2,  -1,  0,  -1, 1 },
    { NULL, 0, {0,0,0}, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void lsp_free_entries(void)
{
    for (int i = 0; i < lsp_n; i++) { free(lsp_entries[i]); lsp_entries[i] = NULL; }
    lsp_n = 0;
}

void construct_schedule_from_pending_map_locked_input(const lv_lsp_test_case_t *tc)
{
    lsp_free_entries();
    lsp_sched_calls = 0; lsp_sched_ap = -1; lsp_sched_dur = lsp_sched_int = 0;
    memset(lsp_sched_mac, 0, sizeof(lsp_sched_mac));
    memset(lsp_app_buf, 0, sizeof(lsp_app_buf));

    struct wifi_app *app = (struct wifi_app *)lsp_app_buf;
    app->data.u.levl.num_current_sounding = tc->num_cur;
    app->data.u.levl.max_num_csi_clients = tc->max_cli;
    app->data.u.levl.pending_mac_map = (tc->null_mode == 2) ? NULL : (void *)lsp_app_buf;  /* any non-NULL token */

    for (int i = 0; i < tc->n; i++) {
        levl_sched_data_t *e = (levl_sched_data_t *)calloc(1, sizeof(levl_sched_data_t));
        e->mac_addr[0] = 0x02; e->mac_addr[4] = (unsigned char)(0x10 + i); e->mac_addr[5] = tc->mac5[i];
        e->duration = 5000 + i; e->interval = 200 + i;
        lsp_entries[lsp_n++] = e;
    }
}

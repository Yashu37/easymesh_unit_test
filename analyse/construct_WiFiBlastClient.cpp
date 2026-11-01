/*
 * TEST CASES / CONSTRUCTOR: construct_WiFiBlastClient
 *
 * Stand-ins: g_active_msmt (wbc_mgr_buf), wifi_mgr (wbc_wmgr_buf), wifi_ctrl
 * (wbc_wctrl_buf, holds apps_mgr + network_mode), and a wifi_app at
 * wbc_app_buf (get_app_by_inst returns it, or NULL for the app_null case).
 * Step 0 is PENDING with a DestMac; all other steps are DONE. The mutex is
 * recursive so the per-iteration lock pattern does not deadlock the test.
 *
 * Cases: ext mode disconnected (msg[256] built, report_error), gw mode
 * disconnected (process_active_msmt_diagnostics), and get_app_by_inst NULL
 * (early return, nothing written).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   wbc_slot_mac[WBC_MAC_SZ + WBC_PAD];
char   wbc_slot_msg[WBC_MSG_SZ + WBC_PAD];
size_t wbc_mac_len, wbc_msg_len;
char   wbc_last_err[256];
int    wbc_report_err, wbc_diag_calls, wbc_last_step_status;
active_msmt_status_t wbc_last_status;
alignas(16) char wbc_mgr_buf[sizeof(wifi_actvie_msmt_t) + WBC_PAD];
alignas(16) char wbc_wmgr_buf[sizeof(wifi_mgr_t) + WBC_PAD];
alignas(16) char wbc_wctrl_buf[sizeof(wifi_ctrl_t) + WBC_PAD];
alignas(16) char wbc_app_buf[sizeof(wifi_app_t) + WBC_PAD];
wifi_app_t *wbc_app;

WiFiBlastClient_test_case_t WiFiBlastClient_suite[] = {
    /* name              app_null ext_mode expect_report expect_diag */
    { "ext_disconnected",  0,      1,       1,            0 },
    { "gw_disconnected",   0,      0,       0,            1 },
    { "app_null",          1,      1,       0,            0 },

    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_WiFiBlastClient_input(const WiFiBlastClient_test_case_t *tc)
{
    memset(wbc_mgr_buf, 0, sizeof(wbc_mgr_buf));
    memset(wbc_wmgr_buf, 0, sizeof(wbc_wmgr_buf));
    memset(wbc_wctrl_buf, 0, sizeof(wbc_wctrl_buf));
    memset(wbc_app_buf, 0, sizeof(wbc_app_buf));

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)wbc_mgr_buf;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g->lock, &attr);
    g->active_msmt.ActiveMsmtEnable = true;
    for (int i = 0; i < MAX_STEP_COUNT; i++) g->active_msmt.StepInstance[i] = 0 /*DONE*/;
    g->active_msmt.StepInstance[0] = 1 /*PENDING*/;
    g->active_msmt.Step[0].ApIndex = 7;
    unsigned char mac[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    memcpy(g->active_msmt.Step[0].DestMac, mac, 6);

    wifi_ctrl_t *c = (wifi_ctrl_t *)wbc_wctrl_buf;
    c->network_mode = tc->ext_mode ? 1 /*ext*/ : 0;

    wbc_app = tc->app_null ? NULL : (wifi_app_t *)wbc_app_buf;

    wbc_mac_len = wbc_msg_len = 0;
    wbc_last_err[0] = 0;
    wbc_report_err = wbc_diag_calls = 0;
    wbc_last_status = ACTIVE_MSMT_STATUS_UNDEFINED;
    wbc_last_step_status = -1;
}

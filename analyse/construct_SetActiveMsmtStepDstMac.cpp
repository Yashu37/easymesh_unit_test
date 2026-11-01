/*
 * TEST CASES / CONSTRUCTOR: construct_SetActiveMsmtStepDstMac
 *
 * g_active_msmt stand-in is at sad_mgr_buf, the wifi_mgr stand-in at
 * sad_wmgr_buf, and DstMac in sad_dst_buf (runner poisons past its NUL).
 * getTotalNumberVAPs() is 0, so no client is ever found; the branch is
 * chosen by network_mode (ext -> msg[256] path, else -> offline diag path).
 *
 * Cases: invalid step (early return), ext mode not-found (msg built,
 * report_error), gw mode not-found (process_active_msmt_diagnostics), a
 * 12-hex DstMac, and a colon DstMac (both parsed into DestMac).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   sad_slot[SAD_SLOT_SZ + SAD_PAD];
size_t sad_msg_len;
char   sad_last_err[256];
int    sad_report_err, sad_diag_calls, sad_last_step_status;
active_msmt_status_t sad_last_status;
alignas(16) char sad_mgr_buf[sizeof(wifi_actvie_msmt_t) + SAD_PAD];
alignas(16) char sad_wmgr_buf[sizeof(wifi_mgr_t) + SAD_PAD];
alignas(16) char sad_dst_buf[64 + SAD_PAD];

SetActiveMsmtStepDstMac_test_case_t SetActiveMsmtStepDstMac_suite[] = {
    /* name            invalid ext_mode dst_mac               expect_mac                      */
    { "invalid_step",     1,    1,      "10:11:12:13:14:15",  {0,0,0,0,0,0} },
    { "ext_not_found",    0,    1,      "10:11:12:13:14:15",  {0x10,0x11,0x12,0x13,0x14,0x15} },
    { "gw_not_found",     0,    0,      "aa:bb:cc:dd:ee:ff",  {0xaa,0xbb,0xcc,0xdd,0xee,0xff} },
    { "hex12_form",       0,    1,      "a0a1a2a3a4a5",       {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5} },
    { "gw_hex12",         0,    0,      "010203040506",       {0x01,0x02,0x03,0x04,0x05,0x06} },

    { NULL, 0, 0, NULL, {0} }  /* sentinel */
};

#define SAD_STEP 5

void construct_SetActiveMsmtStepDstMac_input(const SetActiveMsmtStepDstMac_test_case_t *tc)
{
    memset(sad_mgr_buf, 0, sizeof(sad_mgr_buf));
    memset(sad_wmgr_buf, 0, sizeof(sad_wmgr_buf));
    memset(sad_dst_buf, 0, sizeof(sad_dst_buf));

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)sad_mgr_buf;
    pthread_mutex_init(&g->lock, NULL);
    g->active_msmt.StepInstance[SAD_STEP] = tc->invalid ? 2 /*INVALID*/ : 1 /*PENDING*/;
    g->active_msmt.Step[SAD_STEP].StepId = 42;

    wifi_mgr_t *m = (wifi_mgr_t *)sad_wmgr_buf;
    m->ctrl.network_mode = tc->ext_mode ? 1 /*rdk_dev_mode_type_ext*/ : 0;

    snprintf(sad_dst_buf, 64, "%s", tc->dst_mac);

    sad_msg_len = 0;
    sad_last_err[0] = 0;
    sad_report_err = 0;
    sad_diag_calls = 0;
    sad_last_status = ACTIVE_MSMT_STATUS_UNDEFINED;
    sad_last_step_status = -1;
}

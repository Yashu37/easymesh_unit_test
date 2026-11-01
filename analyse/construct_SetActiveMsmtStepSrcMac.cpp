/*
 * TEST CASES / CONSTRUCTOR: construct_SetActiveMsmtStepSrcMac
 *
 * g_active_msmt stand-in is at ssm_mgr_buf; SrcMac is in ssm_src_buf (runner
 * poisons past its NUL). StepIns = 5.
 *
 * Cases: colon MAC, upper-case colon, 12-hex, and an empty string (bmac 0s).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char ssm_mgr_buf[sizeof(wifi_actvie_msmt_t) + SSM_PAD];
alignas(16) char ssm_src_buf[64 + SSM_PAD];

SetActiveMsmtStepSrcMac_test_case_t SetActiveMsmtStepSrcMac_suite[] = {
    /* name           src_mac               expect_mac                      */
    { "colon_form",   "10:11:12:13:14:15",  {0x10,0x11,0x12,0x13,0x14,0x15} },
    { "colon_upper",  "AA:BB:CC:DD:EE:FF",  {0xaa,0xbb,0xcc,0xdd,0xee,0xff} },
    { "hex12_form",   "a0a1a2a3a4a5",       {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5} },
    { "empty_src",    "",                   {0,0,0,0,0,0} },

    { NULL, NULL, {0} }  /* sentinel */
};

void construct_SetActiveMsmtStepSrcMac_input(const SetActiveMsmtStepSrcMac_test_case_t *tc)
{
    memset(ssm_mgr_buf, 0, sizeof(ssm_mgr_buf));
    memset(ssm_src_buf, 0, sizeof(ssm_src_buf));
    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)ssm_mgr_buf;
    pthread_mutex_init(&g->lock, NULL);
    snprintf(ssm_src_buf, 64, "%s", tc->src_mac);
}

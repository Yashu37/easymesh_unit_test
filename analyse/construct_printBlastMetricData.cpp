/*
 * TEST CASES / CONSTRUCTOR: construct_printBlastMetricData
 *
 * blaster_stats (pbm_bs_buf) carries active_msmt.PlanId + curStepData.StepId;
 * staData (pbm_sd_buf) is a blaster_hashmap_t; wifi_mgr (pbm_wmgr_buf) holds
 * the CCSP trace hooks; wifi_ctrl (pbm_wctrl_buf) sets network_mode (gw -> 16
 * byte PlanId copy, ext -> 36). All driven with activeClient=false, so the
 * radio/client block is skipped and only PlanId (to_plan_char) is written.
 *
 * Cases: gw plan, ext plan, and NULL staData (CcspTraceError + early return).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char pbm_wmgr_buf[sizeof(wifi_mgr_t) + PBM_PAD];
alignas(16) char pbm_wctrl_buf[sizeof(wifi_ctrl_t) + PBM_PAD];
alignas(16) char pbm_bs_buf[sizeof(wifi_actvie_msmt_t) + PBM_PAD];
alignas(16) char pbm_sd_buf[sizeof(blaster_hashmap_t) + PBM_PAD];
unsigned int pbm_num_samples, pbm_num_radios;
int pbm_info_calls, pbm_debug_calls, pbm_err_calls;

static void pbm_info(const char *f, ...)  { (void)f; pbm_info_calls++; }
static void pbm_debug(const char *f, ...) { (void)f; pbm_debug_calls++; }
static void pbm_error(const char *f, ...) { (void)f; pbm_err_calls++; }

printBlastMetricData_test_case_t printBlastMetricData_suite[] = {
    /* name        gw    null_data  expect_info_ge  expect_err */
    { "gw_plan",    1,    0,         1,              0 },
    { "ext_plan",   0,    0,         1,              0 },
    { "null_data",  0,    1,         0,              1 },

    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_printBlastMetricData_input(const printBlastMetricData_test_case_t *tc)
{
    memset(pbm_wmgr_buf, 0, sizeof(pbm_wmgr_buf));
    memset(pbm_wctrl_buf, 0, sizeof(pbm_wctrl_buf));
    memset(pbm_bs_buf, 0, sizeof(pbm_bs_buf));
    memset(pbm_sd_buf, 0, sizeof(pbm_sd_buf));

    wifi_mgr_t *m = (wifi_mgr_t *)pbm_wmgr_buf;
    m->wifi_ccsp.desc.CcspTraceInfoRdkb_fn  = pbm_info;
    m->wifi_ccsp.desc.CcspTraceDebugRdkb_fn = pbm_debug;
    m->wifi_ccsp.desc.CcspTraceErrorRdkb_fn = pbm_error;

    wifi_ctrl_t *c = (wifi_ctrl_t *)pbm_wctrl_buf;
    c->network_mode = tc->gw ? 0 /*gw*/ : 1 /*ext*/;

    wifi_actvie_msmt_t *bs = (wifi_actvie_msmt_t *)pbm_bs_buf;
    memset(bs->active_msmt.PlanId, 'P', PLAN_ID_LENGTH - 1);   /* source plan chars */
    bs->active_msmt.PlanId[PLAN_ID_LENGTH - 1] = 0;
    bs->curStepData.StepId = 5;

    pbm_num_samples = 3;
    pbm_num_radios = 3;
    pbm_info_calls = pbm_debug_calls = pbm_err_calls = 0;
}

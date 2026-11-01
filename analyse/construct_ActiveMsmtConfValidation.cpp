/*
 * TEST CASES / CONSTRUCTOR: construct_ActiveMsmtConfValidation
 *
 * cfg is a full active_msmt_t at the start of amc_cfg_buf (runner poisons
 * past the struct). A valid config is built, then each case perturbs one
 * field to hit a specific error branch.
 *
 * Cases: NULL cfg, all-valid, empty PlanId, too-long PlanId, bad sample
 * count, bad duration, bad ratio, bad packet size, an invalid-length MAC in
 * one step, and PlanId filling all 38 bytes with no NUL (strlen over-read
 * guarded by the struct-tail poison plus the next field).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   amc_slot[AMC_SLOT_SZ + AMC_PAD];
size_t amc_msg_len;
char   amc_last_err[256];
int    amc_report_err, amc_report_all, amc_step_invalid;
active_msmt_status_t amc_last_status;
alignas(16) char amc_cfg_buf[sizeof(active_msmt_t) + AMC_PAD];

ActiveMsmtConfValidation_test_case_t ActiveMsmtConfValidation_suite[] = {
    /* name            kind                 expect_ret  expect_err_sub            */
    { "null_cfg",       AMC_NULL,            -1,  ""                              },
    { "all_valid",      AMC_VALID,            0,  ""                              },
    { "empty_planid",   AMC_EMPTY_PLAN,      -1,  "Invalid length of PlanID"      },
    { "long_planid",    AMC_LONG_PLAN,       -1,  "Invalid length of PlanID"      },
    { "bad_samples",    AMC_BAD_SAMPLES,     -1,  "Invalid Sample count"          },
    { "bad_duration",   AMC_BAD_DURATION,    -1,  "Invalid Duration"              },
    { "bad_ratio",      AMC_BAD_RATIO,       -1,  "Invalid Duration/Sample"       },
    { "bad_pktsize",    AMC_BAD_PKTSIZE,     -1,  "Invalid Packet size"           },
    { "bad_step_mac",   AMC_BAD_STEP_MAC,     0,  "Invalid MAC address"           },
    { "planid_no_nul",  AMC_PLAN_NO_NUL,     -1,  "Invalid length of PlanID"      },

    { NULL, AMC_VALID, 0, NULL }  /* sentinel */
};

void construct_ActiveMsmtConfValidation_input(const ActiveMsmtConfValidation_test_case_t *tc)
{
    memset(amc_cfg_buf, 0, sizeof(amc_cfg_buf));
    active_msmt_t *c = (active_msmt_t *)amc_cfg_buf;

    /* a valid baseline */
    snprintf((char *)c->PlanId, PLAN_ID_LENGTH, "PLAN-0001");
    c->ActiveMsmtNumberOfSamples = 10;
    c->ActiveMsmtSampleDuration  = 5000;
    c->ActiveMsmtPktSize         = 1000;
    for (int i = 0; i < MAX_STEP_COUNT; i++) c->Step[i].DestMac[0] = 0;   /* empty MACs = valid */

    switch (tc->kind) {
    case AMC_EMPTY_PLAN:   c->PlanId[0] = 0; break;
    case AMC_LONG_PLAN:    memset(c->PlanId, 'A', PLAN_ID_LENGTH - 1); c->PlanId[PLAN_ID_LENGTH - 1] = 0; break;
    case AMC_BAD_SAMPLES:  c->ActiveMsmtNumberOfSamples = 200; break;
    case AMC_BAD_DURATION: c->ActiveMsmtSampleDuration = 500; break;
    case AMC_BAD_RATIO:    c->ActiveMsmtNumberOfSamples = 100; c->ActiveMsmtSampleDuration = 1000; break; /* 10ms < 100 */
    case AMC_BAD_PKTSIZE:  c->ActiveMsmtPktSize = 40; break;
    case AMC_BAD_STEP_MAC: memcpy(c->Step[3].DestMac, "ZZZ", 3); break;   /* len 3 -> invalid */
    case AMC_PLAN_NO_NUL:  memset(c->PlanId, 'B', PLAN_ID_LENGTH); break;  /* no NUL in 38 bytes */
    default: break;
    }

    amc_msg_len = 0;
    amc_last_err[0] = 0;
    amc_report_err = amc_report_all = amc_step_invalid = 0;
    amc_last_status = ACTIVE_MSMT_STATUS_UNDEFINED;
}

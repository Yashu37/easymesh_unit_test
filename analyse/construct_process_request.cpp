/*
 * TEST CASES / CONSTRUCTOR: construct_process_request
 *
 * cfg is an active_msmt_t at prq_cfg_buf (runner poisons past it); the
 * g_active_msmt / wifi_mgr stand-ins are at prq_mgr_buf / prq_wmgr_buf. The
 * health-stats branch is chosen with prq_health_fail / prq_high_cpu.
 *
 * Cases: gw health-fail (msg "Failed to fill in health stats"), ext
 * health-fail (same + report_all_steps + webconfig_state), high CPU
 * (BUSY msg), low memory (BUSY msg), ext invalid conf (early return),
 * and the success path (no msg, WiFiBlastClient called).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

char   prq_slot[PRQ_SLOT_SZ + PRQ_PAD];
size_t prq_msg_len;
char   prq_last_err[256];
int    prq_report_all, prq_blast_calls;
int    prq_health_fail, prq_high_cpu, prq_conf_invalid;
int    prq_low_mem_force;
alignas(16) char prq_cfg_buf[sizeof(active_msmt_t) + PRQ_PAD];
alignas(16) char prq_mgr_buf[sizeof(wifi_actvie_msmt_t) + PRQ_PAD];
alignas(16) char prq_wmgr_buf[sizeof(wifi_mgr_t) + PRQ_PAD];

process_request_test_case_t process_request_suite[] = {
    /* name            ext  health_fail high_cpu low_mem conf_invalid  want_msg_sub        */
    { "gw_health_fail",  0,   1,          0,      0,      0,  "Failed to fill in health stats" },
    { "ext_health_fail", 1,   1,          0,      0,      0,  "Failed to fill in health stats" },
    { "high_cpu",        0,   0,          1,      0,      0,  "high CPU usage"                 },
    { "low_mem",         0,   0,          0,      1,      0,  "low free RAM memory"            },
    { "ext_bad_conf",    1,   0,          0,      0,      1,  ""                               },
    { "success",         0,   0,          0,      0,      0,  ""                               },

    { NULL, 0, 0, 0, 0, 0, NULL }  /* sentinel */
};

void construct_process_request_input(const process_request_test_case_t *tc)
{
    memset(prq_cfg_buf, 0, sizeof(prq_cfg_buf));
    memset(prq_mgr_buf, 0, sizeof(prq_mgr_buf));
    memset(prq_wmgr_buf, 0, sizeof(prq_wmgr_buf));

    active_msmt_t *cfg = (active_msmt_t *)prq_cfg_buf;
    cfg->ActiveMsmtEnable = true;
    cfg->ActiveMsmtSampleDuration = 5000;
    cfg->ActiveMsmtNumberOfSamples = 10;
    cfg->ActiveMsmtPktSize = 1000;
    snprintf((char *)cfg->PlanId, PLAN_ID_LENGTH, "PLAN-1");
    for (int i = 0; i < MAX_STEP_COUNT; i++) cfg->Step[i].DestMac[0] = 0;   /* no steps */

    wifi_actvie_msmt_t *g = (wifi_actvie_msmt_t *)prq_mgr_buf;
    pthread_mutex_init(&g->lock, NULL);

    wifi_mgr_t *m = (wifi_mgr_t *)prq_wmgr_buf;
    m->ctrl.network_mode = tc->ext ? 1 /*ext*/ : 0;
    m->ctrl.webconfig_state = 0;

    prq_health_fail = tc->health_fail;
    prq_high_cpu    = tc->high_cpu;
    prq_conf_invalid = tc->conf_invalid;
    /* low_mem: force util_mem < threshold via the success calc path; the stub
     * DeviceMemory_DataGet sets util_mem=500000 which is < MEM_THRESHOLD? no
     * (threshold 1000). For low_mem we instead rely on high_cpu=0 and a tiny
     * threshold is not adjustable here, so low_mem uses health_fail=0 and the
     * util_mem default 500000 >= 1000 -> would NOT hit low_mem. Adjust: */
    if (tc->low_mem) prq_low_mem_force = 1; else prq_low_mem_force = 0;

    prq_msg_len = 0;
    prq_last_err[0] = 0;
    prq_report_all = prq_blast_calls = 0;
}

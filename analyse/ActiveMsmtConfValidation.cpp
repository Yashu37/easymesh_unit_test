/*
 * HANDLER: ActiveMsmtConfValidation
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local msg[256] is written only by snprintf(msg, sizeof(msg), ..)
 * on each validation error (bounded). Reads cfg->PlanId (strlen) and
 * cfg->Step[i].DestMac (strlen / %s) across MAX_STEP_COUNT steps.
 *
 * Redirect: snprintf() -> amc_snprintf(): real vsnprintf on the runner slot
 * amc_slot (SAME size, 256), then copied into msg. The RUNNER poisons
 * amc_slot past 256 and the caller's cfg struct past its size. msg is also
 * guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): the report / status helpers
 * are file-local no-op recorders; PLAN_ID_LENGTH / MAX_STEP_COUNT /
 * MAC_ADDRESS_LENGTH and the status enum come from common.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include "common.h"

/* --- scaffolding --- */
#define RETURN_OK   0
#define RETURN_ERR -1
#define ACTIVE_MSMT_STEP_INVALID 2          /* active_msmt_step_status_t, wifi_blaster.h */

static void SetActiveMsmtStatus(const char *f, active_msmt_status_t s) { (void)f; amc_last_status = s; }
static void active_msmt_set_step_status(const char *f, unsigned int i, int v) { (void)f; (void)i; (void)v; amc_step_invalid++; }
static void active_msmt_report_error(const char *f, unsigned char *plan, void *step, char *msg, active_msmt_status_t s)
{
    (void)f; (void)plan; (void)step; (void)s;
    amc_report_err++;
    snprintf(amc_last_err, sizeof(amc_last_err), "%s", msg);
}
static void active_msmt_report_all_steps(active_msmt_t *cfg, char *msg, active_msmt_status_t s)
{
    (void)cfg; (void)s;
    amc_report_all++;
    snprintf(amc_last_err, sizeof(amc_last_err), "%s", msg);
}

static int amc_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r;
    va_list ap;
    if (sz > AMC_SLOT_SZ) sz = AMC_SLOT_SZ;
    memset(amc_slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(amc_slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, amc_slot, sz);
    amc_msg_len = strnlen(amc_slot, sz);
    return r;
}
#define snprintf(o, n, ...)  amc_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c --- */
int ActiveMsmtConfValidation(active_msmt_t *cfg)
{
    int len;
    char msg[256] = {};

    if (cfg == NULL) {
        return RETURN_ERR;
    }
    if (((len = strlen((char *)cfg->PlanId)) < 1) || len > PLAN_ID_LENGTH - 2) {
        snprintf(msg, sizeof(msg), "Invalid length of PlanID [%d]. Expected in range [1..%d]",
            len, PLAN_ID_LENGTH - 2);
        goto Error;
    }

    if ((cfg->ActiveMsmtNumberOfSamples < 1) || (cfg->ActiveMsmtNumberOfSamples > 100)) {
        snprintf(msg, sizeof(msg), "Invalid Sample count [%d]. Expected in range [1..100]",
            cfg->ActiveMsmtNumberOfSamples);
        goto Error;
    }

    if ((cfg->ActiveMsmtSampleDuration < 1000) || (cfg->ActiveMsmtSampleDuration > 10000)) {
        snprintf(msg, sizeof(msg), "Invalid Duration [%d]ms. Expected in range [1000..10000]",
            cfg->ActiveMsmtSampleDuration);
        goto Error;
    }

    if ((cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples) < 100) {
        snprintf(msg, sizeof(msg), "Invalid Duration/Sample_count ratio [%d/%d = %d]ms. Expected >= 100",
            cfg->ActiveMsmtSampleDuration, cfg->ActiveMsmtNumberOfSamples,
            cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples);
        goto Error;
    }

    if (cfg->ActiveMsmtPktSize < 64 || cfg->ActiveMsmtPktSize > 1470) {
        snprintf(msg, sizeof(msg), "Invalid Packet size [%d]bytes. Expected in range [64..1470]",
            cfg->ActiveMsmtPktSize);
        goto Error;
    }

    for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {
        len = strlen((char *) cfg->Step[i].DestMac);

        /* MAC could be 0 or XXXXXXXXXXXX */
        if (len != 0 && len != MAC_ADDRESS_LENGTH - 1) {
            snprintf(msg, sizeof(msg), "Invalid MAC address [%s]", cfg->Step[i].DestMac);
            active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[i], msg, ACTIVE_MSMT_STATUS_WRONG_ARG);
            active_msmt_set_step_status(__func__, i, ACTIVE_MSMT_STEP_INVALID);
            continue;
        }

        if (cfg->Step[i].StepId > INT_MAX) {
            snprintf(msg, sizeof(msg), "Invalid StepID [%d]. Expected in range [0..INT_MAX]", cfg->Step[i].StepId);
            active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[i], msg, ACTIVE_MSMT_STATUS_WRONG_ARG);
            active_msmt_set_step_status(__func__, i, ACTIVE_MSMT_STEP_INVALID);
            continue;
        }
    }

    SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);

    return RETURN_OK;

Error:
    active_msmt_report_all_steps(cfg, msg, ACTIVE_MSMT_STATUS_WRONG_ARG);

    return RETURN_ERR;
}

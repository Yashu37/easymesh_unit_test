/*
 * HANDLER: process_request
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). No fixes. Local
 * msg[256] is written only by snprintf(msg, sizeof(msg), ...) in the three
 * health-stats failure branches (all bounded).
 *
 * Redirect: snprintf() -> prq_snprintf(): real vsnprintf on the runner slot
 * prq_slot (SAME size, 256), then copied into msg. The RUNNER poisons
 * prq_slot past 256 and the caller-owned cfg / g_active_msmt / wifi_mgr
 * stand-ins past their sizes. msg is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): every external helper is a
 * file-local stub. The health-stats path is selected by prq_health_fail
 * (DeviceMemory_DataGet returns false -> "Failed to fill in health stats").
 * WiFiBlastClient() is a local no-op stub (not the heavy real one).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdint.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define RETURN_OK 0
#define rdk_dev_mode_type_ext 1
#define ctrl_webconfig_state_blaster_cfg_complete_rsp_pending 0x40000
#define WIFI_BLASTER_CPU_CALC_PERIOD 1
#define WIFI_BLASTER_CPU_THRESHOLD 80
#define WIFI_BLASTER_MEM_THRESHOLD 1000

static void prq_print(int module, const char *fmt, ...)
{ char sc[1024]; va_list ap; (void)module; va_start(ap, fmt); vsnprintf(sc, sizeof(sc), fmt, ap); va_end(ap); }
#define wifi_util_info_print   prq_print
#define wifi_util_dbg_print    prq_print
#define wifi_util_error_print  prq_print

static void *get_wifi_blaster(void) { return prq_mgr_buf; }
static void *get_wifimgr_obj(void)  { return prq_wmgr_buf; }
static void SetBlasterTraceContext(char *a, char *b) { (void)a; (void)b; }
static void blaster_send_telemetry_event(void *g, const char *e) { (void)g; (void)e; }
static void SetActiveMsmtStatus(const char *f, active_msmt_status_t s) { (void)f; (void)s; }
static void ResetActiveMsmtStepInstances(void) {}
static int  ActiveMsmtConfValidation(active_msmt_t *cfg) { (void)cfg; return prq_conf_invalid ? -1 : RETURN_OK; }
static void SetActiveMsmtSampleDuration(unsigned int d) { (void)d; }
static void SetBlasterMqttTopic(char *t) { (void)t; }
static void SetActiveMsmtPktSize(unsigned int s) { (void)s; }
static void SetActiveMsmtNumberOfSamples(unsigned int n) { (void)n; }
static void SetActiveMsmtPlanID(char *p) { (void)p; }
static void SetActiveMsmtStepID(unsigned int id, unsigned int i) { (void)id; (void)i; }
static void SetActiveMsmtStepDstMac(char *m, unsigned int i) { (void)m; (void)i; }
static void SetActiveMsmtStepSrcMac(char *m, unsigned int i) { (void)m; (void)i; }
static void SetActiveMsmtEnable(bool e) { (void)e; }
static bool DeviceMemory_DataGet(unsigned int *util_mem) { if (prq_health_fail) return false; *util_mem = prq_low_mem_force ? 500 : 500000; return true; }
static bool DeviceLoad_DataGet(void *res) { (void)res; return true; }
static bool active_msmt_calc_cpu_util(int period, unsigned int *util_cpu) { (void)period; *util_cpu = prq_high_cpu ? 95 : 10; return true; }
static void active_msmt_report_all_steps(active_msmt_t *cfg, char *msg, active_msmt_status_t s)
{ (void)cfg; (void)s; prq_report_all++; snprintf(prq_last_err, sizeof(prq_last_err), "%s", msg); }
static void active_msmt_log_message(int level, const char *fmt, ...) { (void)level; (void)fmt; }
static void WiFiBlastClient(void) { prq_blast_calls++; }

static int prq_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r; va_list ap;
    if (sz > PRQ_SLOT_SZ) sz = PRQ_SLOT_SZ;
    memset(prq_slot, 0, sz);
    va_start(ap, fmt); r = vsnprintf(prq_slot, sz, fmt, ap); va_end(ap);
    memcpy(out, prq_slot, sz);
    prq_msg_len = strnlen(prq_slot, sz);
    return r;
}
#define snprintf(o, n, ...)  prq_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
void process_request(active_msmt_t *cfg)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *act_msmt = &g_active_msmt->active_msmt;
    active_msmt_status_t status;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    wifi_ctrl_t *ctrl = &mgr->ctrl;
    char msg[256] = {};
    bool report = false;

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Enter\n", __func__, __LINE__);

    pthread_mutex_lock(&g_active_msmt->lock);

    wifi_util_info_print(WIFI_BLASTER, "%s:%d trace headers are %s and %s\n", __func__, __LINE__,
        cfg->t_header.traceParent, cfg->t_header.traceState);
    SetBlasterTraceContext(cfg->t_header.traceParent, cfg->t_header.traceState);
    blaster_send_telemetry_event(g_active_msmt, "TRACE_WIFIBLAST_ENABLED");
    wifi_util_dbg_print(WIFI_BLASTER,"%s:%d blast is enabled\n", __func__, __LINE__);
    SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
    ResetActiveMsmtStepInstances();

    if (ctrl->network_mode == rdk_dev_mode_type_ext) {

        if (ActiveMsmtConfValidation(cfg) != RETURN_OK) {
            wifi_util_error_print(WIFI_BLASTER, "%s:%d Active measurement conf is invalid!\n", __func__, __LINE__);
            mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;
            pthread_mutex_unlock(&g_active_msmt->lock);
            return;
        }

        SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples);
        SetBlasterMqttTopic((char *)cfg->blaster_mqtt_topic);
    } else {
        SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration);
    }

    SetActiveMsmtPktSize(cfg->ActiveMsmtPktSize);
    SetActiveMsmtNumberOfSamples(cfg->ActiveMsmtNumberOfSamples);
    SetActiveMsmtPlanID((char *)cfg->PlanId);
    wifi_util_info_print(WIFI_BLASTER, "%s:%d trace headers are %s and %s\n", __func__, __LINE__,
        cfg->t_header.traceParent, cfg->t_header.traceState);
    SetBlasterTraceContext(cfg->t_header.traceParent, cfg->t_header.traceState);
    wifi_util_info_print(WIFI_BLASTER, "Done Setting SetBlasterTraceContext\n");

    for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {
        if(strlen((char *) cfg->Step[i].DestMac) != 0) {
            SetActiveMsmtStepID(cfg->Step[i].StepId, i);
            SetActiveMsmtStepDstMac((char *)cfg->Step[i].DestMac, i);
            SetActiveMsmtStepSrcMac((char *)cfg->Step[i].SrcMac, i);
        }
    }

    SetActiveMsmtEnable(cfg->ActiveMsmtEnable);

    if (DeviceMemory_DataGet(&act_msmt->ActiveMsmtResources.util_mem) != true ||
        DeviceLoad_DataGet(&act_msmt->ActiveMsmtResources) != true ||
        active_msmt_calc_cpu_util(WIFI_BLASTER_CPU_CALC_PERIOD, &act_msmt->ActiveMsmtResources.util_cpu) != true) {

        snprintf(msg, sizeof(msg), "Failed to fill in health stats");
        status = ACTIVE_MSMT_STATUS_FAILED;
        report = true;

    } else if (act_msmt->ActiveMsmtResources.util_cpu > WIFI_BLASTER_CPU_THRESHOLD) {

        snprintf(msg, sizeof(msg), "Skip because of high CPU usage [%u]%%. Threshold [%d]%%",
            act_msmt->ActiveMsmtResources.util_cpu, WIFI_BLASTER_CPU_THRESHOLD);
        status = ACTIVE_MSMT_STATUS_BUSY;
        report = true;

    } else if (act_msmt->ActiveMsmtResources.util_mem < WIFI_BLASTER_MEM_THRESHOLD) {

        snprintf(msg, sizeof(msg), "Skip because of low free RAM memory [%u]KB.  Threshold [%d]KB",
            act_msmt->ActiveMsmtResources.util_mem, WIFI_BLASTER_MEM_THRESHOLD);
        status = ACTIVE_MSMT_STATUS_BUSY;
        report = true;
    }

    if (report == true) {

        if (ctrl->network_mode == rdk_dev_mode_type_ext) {
            active_msmt_report_all_steps(cfg, msg, status);
            mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;
        }
        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d %s\n" ,__FUNCTION__, __LINE__, msg);
        pthread_mutex_unlock(&g_active_msmt->lock);
        return;
    }

    pthread_mutex_unlock(&g_active_msmt->lock);

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Starting to proceed PlanId [%s]\n", __func__, __LINE__, cfg->PlanId);
    WiFiBlastClient();
    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Done PlanId [%s]\n", __func__, __LINE__, cfg->PlanId);

    pthread_mutex_lock(&g_active_msmt->lock);
    blaster_send_telemetry_event(g_active_msmt, "TRACE_WIFIBLAST_NOT_ENABLED");
    pthread_mutex_unlock(&g_active_msmt->lock);

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Exit\n", __func__, __LINE__);
}

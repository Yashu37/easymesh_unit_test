/*
 * HANDLER: SetActiveMsmtStepDstMac
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local arrays:
 *   - mac_address_t bmac (6 bytes) <- blaster_str_to_mac_bytes(DstMac, bmac)
 *     (indices 0..5), then memcpy'd into cfg->Step[StepIns].DestMac.
 *   - char msg[256] (only in the "client not found / ext mode" branch) <-
 *     snprintf(msg, sizeof(msg), "Failed to find MAC in STA associated list").
 *
 * The RUNNER poisons the caller's DstMac past its NUL, the g_active_msmt
 * stand-in past its size, and the msg write slot past 256. bmac and msg are
 * also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): every external helper is a
 * file-local stub. getTotalNumberVAPs() returns 0 so the VAP-scan loop body
 * never runs; is_blaster_device_associated()/getVapInfo()/SetActiveMAPIndex()
 * exist only for compilation. blaster_str_to_mac_bytes() parses the MAC into
 * bmac; the msg snprintf is redirected to a runner slot of the same size.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define ULONG unsigned long
#define UNDEFINED_MLD_ID 0xffff
#define ACTIVE_MSMT_STEP_PENDING 1
#define ACTIVE_MSMT_STEP_INVALID 2
#define rdk_dev_mode_type_ext 1
#define VAP_INDEX(cap, i)  (i)
typedef struct {                             // only a pointer is held; deref path is never reached (stub returns false)
	struct { struct { struct { struct { int mld_id; } common_info; } mld_info; } bss_info; } u;
} wifi_vap_info_t;

static void sad_print(int module, const char *fmt, ...)
{
    char scratch[1024]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print  sad_print

static void *get_wifi_blaster(void) { return sad_mgr_buf; }
static void *get_wifimgr_obj(void)  { return sad_wmgr_buf; }
static int   getTotalNumberVAPs(void) { return 0; }   /* skip the VAP-scan loop body */
static bool  is_blaster_device_associated(unsigned int ap, unsigned char *mac, bool *is_mlo) { (void)ap;(void)mac;(void)is_mlo; return false; }
static wifi_vap_info_t *getVapInfo(unsigned int ap) { (void)ap; return NULL; }
static void  SetActiveMAPIndex(unsigned int mld, ULONG step) { (void)mld; (void)step; }
static void  SetActiveMsmtStatus(const char *f, active_msmt_status_t s) { (void)f; sad_last_status = s; }
static void  active_msmt_set_step_status(const char *f, ULONG i, int v) { (void)f; (void)i; sad_last_step_status = v; }
static void  active_msmt_report_error(const char *f, unsigned char *plan, void *step, char *msg, active_msmt_status_t s)
{ (void)f;(void)plan;(void)step;(void)s; sad_report_err++; snprintf(sad_last_err, sizeof(sad_last_err), "%s", msg); }
static void  active_msmt_log_message(int level, const char *fmt, ...) { (void)level; (void)fmt; }
static void  process_active_msmt_diagnostics(int ap) { (void)ap; sad_diag_calls++; }
static void  stream_client_msmt_data(bool b) { (void)b; }

/* bmac writer: parse the MAC string (indices 0..5) */
static void blaster_str_to_mac_bytes(char *key, unsigned char *bmac)
{
    unsigned int m[6] = {0};
    if (strlen(key) > 12)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    for (int i = 0; i < 6; i++) bmac[i] = (unsigned char)m[i];
}

/* redirect: write msg into a runner slot of the same size */
static int sad_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    int r; va_list ap;
    if (sz > SAD_SLOT_SZ) sz = SAD_SLOT_SZ;
    memset(sad_slot, 0, sz);
    va_start(ap, fmt); r = vsnprintf(sad_slot, sz, fmt, ap); va_end(ap);
    memcpy(out, sad_slot, sz);
    sad_msg_len = strnlen(sad_slot, sz);
    return r;
}
#define snprintf(o, n, ...)  sad_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c --- */
void SetActiveMsmtStepDstMac(char *DstMac, ULONG StepIns)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    mac_address_t bmac;
    int i, j = 0;
    bool client_found = false;
    UINT mld_id = UNDEFINED_MLD_ID;
    wifi_vap_info_t *vap = NULL;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;
    wifi_ctrl_t *ctrl = &mgr->ctrl;

    if (cfg->StepInstance[StepIns] == ACTIVE_MSMT_STEP_INVALID) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Active Measurement Step: %d is invalid. Skipping...\n",
            __func__, __LINE__, StepIns);
        return;
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Step Destination Mac changed to %s for step ins : %d\n", __func__, __LINE__,DstMac,StepIns);

    blaster_str_to_mac_bytes(DstMac, bmac);
    cfg->Step[StepIns].ApIndex = -1;

    memset(cfg->Step[StepIns].DestMac, 0, sizeof(mac_address_t));
    memcpy(cfg->Step[StepIns].DestMac, bmac, sizeof(mac_address_t));

    active_msmt_set_step_status(__func__, StepIns, ACTIVE_MSMT_STEP_PENDING);
    for (i = 0; i < MAX_NUM_RADIOS - 1; i++) {
        cfg->Step[StepIns].mldApIndex[i] = -1;
    }
    cfg->Step[StepIns].isMLO = false;

    for (i = 0; i < (int)getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        if (is_blaster_device_associated(vap_index, bmac, &cfg->Step[StepIns].isMLO) == true) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: found client %s on ap %d\n", __func__, __LINE__, DstMac,vap_index);
            if (cfg->Step[StepIns].isMLO && mld_id == UNDEFINED_MLD_ID) {
                vap = getVapInfo(vap_index);
                if (vap)
                    mld_id = vap->u.bss_info.mld_info.common_info.mld_id;
            }
            // Store associated MLD VAP indices
            // ApIndex is set to the first match and may be reordered to MAP in SetActiveMAPIndex().
            if (!client_found) {
                cfg->Step[StepIns].ApIndex = vap_index;
                client_found = true;
            }
            else if (cfg->Step[StepIns].isMLO && (j < MAX_NUM_RADIOS - 1)){
                cfg->Step[StepIns].mldApIndex[j] = vap_index;
                j++;
            }
        }
    }
    if (client_found) {
        //BCM Specific, pktgen need to be done on MAP interface, reorder if needed
        SetActiveMAPIndex(mld_id, StepIns);
        return;
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: client %s not found \n", __func__, __LINE__, DstMac);

    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        char msg[256] = {};

        snprintf(msg, sizeof(msg), "Failed to find MAC in STA associated list");
        active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[StepIns], msg, ACTIVE_MSMT_STATUS_NO_CLIENT);

        /* Set status as succeed back to be able to procceed other Steps */
        SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
    } else {

        g_active_msmt->curStepData.ApIndex = -1;
        g_active_msmt->curStepData.StepId = cfg->Step[StepIns].StepId;
        memcpy(g_active_msmt->curStepData.DestMac, cfg->Step[StepIns].DestMac, sizeof(mac_address_t));

        /*
        * process_active_msmt_diagnostics and stream_client_msmt_data, both has mutex lock *
        * and unlock.  If anything entered this critical region with holding mutex lock,   *
        * then its waiting to unlock causing infinite loop.  To avoid this loop, we are    *
        * unlocking mutex for the critical region code.                                    *
        */
        pthread_mutex_unlock(&g_active_msmt->lock);
        process_active_msmt_diagnostics(cfg->Step[StepIns].ApIndex);
        stream_client_msmt_data(true);
        pthread_mutex_lock(&g_active_msmt->lock);
    }

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d no need to start pktgen for offline client: %s\n" ,__FUNCTION__, __LINE__, DstMac);
    active_msmt_set_step_status(__func__, StepIns, ACTIVE_MSMT_STEP_INVALID);
}

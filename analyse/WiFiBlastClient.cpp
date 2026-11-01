/*
 * HANDLER: WiFiBlastClient
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local arrays:
 *   - macStr[18] <- snprintf(macStr, sizeof(macStr), MAC_FMT, ...)  (bounded; only on the pktgen path)
 *   - msg[256]   <- snprintf(msg, sizeof(msg), ...)                 (bounded)
 *   - bmac[6]    <- fixed indices 0..5 from curStepData.DestMac
 *
 * This harness drives the "client disconnected" branch (one PENDING step,
 * is_blaster_device_associated()/aap_link() both false, ext network mode),
 * which exercises the msg[256] snprintf and then continues -- it never
 * reaches the radio/pktgen code, so macStr is not written on this path.
 *
 * Redirect: snprintf() -> wbc_snprintf(): real vsnprintf on runner slots of
 * the SAME size (18 -> wbc_slot_mac, 256 -> wbc_slot_msg), then copied back.
 * The RUNNER poisons both slots past their sizes and the caller-owned
 * stand-ins (g_active_msmt, wifi_mgr, wifi_ctrl, wifi_app). macStr/msg/bmac
 * are also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): every external helper is a
 * file-local stub; GetActiveMsmtNumberOfSamples()==0 skips the realloc;
 * is_blaster_device_associated*()==false selects the disconnected branch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define WIFI_APPS    0
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(arg) arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]
#define ACTIVE_MSMT_STEP_DONE    0
#define ACTIVE_MSMT_STEP_PENDING 1
#define ACTIVE_MSMT_STEP_INVALID 2
#define rdk_dev_mode_type_ext    1
#define wifi_app_inst_blaster    0x4
#define RETURN_ERR              -1
typedef char wifi_interface_name_t[32];
typedef struct { unsigned int channel; } wifi_radio_operationParam_t;

static void wbc_print(int module, const char *fmt, ...)
{ char sc[1024]; va_list ap; (void)module; va_start(ap, fmt); vsnprintf(sc, sizeof(sc), fmt, ap); va_end(ap); }
#define wifi_util_dbg_print    wbc_print
#define wifi_util_error_print  wbc_print

static void *get_wifimgr_obj(void)  { return wbc_wmgr_buf; }
static void *get_wifictrl_obj(void) { return wbc_wctrl_buf; }
static void *get_wifi_blaster(void) { return wbc_mgr_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return wbc_app; }
static unsigned int GetActiveMsmtNumberOfSamples(void) { return 0; }   /* skip the realloc block */
static int  isVapEnabled(int ap) { (void)ap; return 0; }
static bool is_blaster_device_associated(int ap, unsigned char *mac, bool *mlo) { (void)ap;(void)mac;(void)mlo; return false; }
static bool is_blaster_device_associated_aap_link(unsigned char *mac, void *step) { (void)mac;(void)step; return false; }
static void process_active_msmt_diagnostics(int ap) { (void)ap; wbc_diag_calls++; }
static void stream_client_msmt_data(bool b) { (void)b; }
static void active_msmt_report_error(const char *f, unsigned char *plan, void *step, char *msg, active_msmt_status_t s)
{ (void)f;(void)plan;(void)step;(void)s; wbc_report_err++; snprintf(wbc_last_err, sizeof(wbc_last_err), "%s", msg); }
static void SetActiveMsmtStatus(const char *f, active_msmt_status_t s) { (void)f; wbc_last_status = s; }
static void active_msmt_set_step_status(const char *f, unsigned int i, int v) { (void)f;(void)i; wbc_last_step_status = v; }
static void active_msmt_log_message(int level, const char *fmt, ...) { (void)level; (void)fmt; }

/* redirect: write macStr/msg into runner slots of the same size */
static int wbc_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    char *slot = (sz == WBC_MAC_SZ) ? wbc_slot_mac : wbc_slot_msg;
    size_t cap = (sz == WBC_MAC_SZ) ? WBC_MAC_SZ : WBC_MSG_SZ;
    if (sz > cap) sz = cap;
    int r; va_list ap;
    memset(slot, 0, sz);
    va_start(ap, fmt); r = vsnprintf(slot, sz, fmt, ap); va_end(ap);
    memcpy(out, slot, sz);
    if (sz == WBC_MAC_SZ) wbc_mac_len = strnlen(slot, sz);
    else                  wbc_msg_len = strnlen(slot, sz);
    return r;
}
#define snprintf(o, n, ...)  wbc_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (truncated at the disconnected-branch continue; the rest is the radio/pktgen path not reached here) --- */
void WiFiBlastClient(void)
{
    char macStr[18] = {'\0'};
    unsigned int StepCount = 0;
    int apIndex = 0;
    unsigned int NoOfSamples = 0, oldNoOfSamples = 0;
    wifi_interface_name_t *interface_name = NULL;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    wifi_ctrl_t *g_wifi_ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;
    wifi_radio_operationParam_t* radioOperation;
    int radio_index;
    char msg[256] = {};
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;
    unsigned int primary_radio_channel;
    (void)g_wifi_mgr; (void)macStr; (void)interface_name; (void)radioOperation; (void)radio_index; (void)primary_radio_channel;

    apps_mgr = &g_wifi_ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    for (StepCount = 0; StepCount < MAX_STEP_COUNT; StepCount++) {
        pthread_mutex_lock(&g_active_msmt->lock);

        if (cfg->ActiveMsmtEnable == false) {
            for (StepCount = StepCount; StepCount < MAX_STEP_COUNT; StepCount++) {
                cfg->StepInstance[StepCount] = ACTIVE_MSMT_STEP_DONE;
            }
            active_msmt_log_message(BLASTER_INFO_LOG, "ActiveMsmtEnable changed from TRUE to FALSE"
                "Setting remaining [%d] step count to 0 and STOPPING further processing\n",
                (MAX_STEP_COUNT - StepCount));
            pthread_mutex_unlock(&g_active_msmt->lock);
            break;
        }

        NoOfSamples = GetActiveMsmtNumberOfSamples();

        if (oldNoOfSamples != NoOfSamples) {
            wifi_app->data.u.blaster.frameCountSample = (pktGenFrameCountSamples *)realloc(wifi_app->data.u.blaster.frameCountSample, (NoOfSamples + 1) * sizeof(pktGenFrameCountSamples));

            if (wifi_app->data.u.blaster.frameCountSample == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "Memory allocation failed for frameCountSample\n");
                pthread_mutex_unlock(&g_active_msmt->lock);
                break;
            }

            memset(wifi_app->data.u.blaster.frameCountSample, 0, (NoOfSamples + 1) * sizeof(pktGenFrameCountSamples));
            oldNoOfSamples = NoOfSamples;
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Size for frameCountSample changed to %d\n", __func__, __LINE__, NoOfSamples);
        }

        if (cfg->StepInstance[StepCount] == ACTIVE_MSMT_STEP_PENDING) {
            mac_address_t bmac;

            wifi_util_dbg_print(WIFI_BLASTER,"%s : %d processing StepCount : %d \n",__func__,__LINE__,StepCount);
            apIndex = cfg->Step[StepCount].ApIndex;

            g_active_msmt->curStepData.ApIndex = apIndex;
            g_active_msmt->curStepData.isMLO = cfg->Step[StepCount].isMLO;
            memcpy(g_active_msmt->curStepData.mldApIndex, cfg->Step[StepCount].mldApIndex,
                sizeof(g_active_msmt->curStepData.mldApIndex));
            wifi_util_error_print(WIFI_BLASTER, "Value of apindex is %d \n", apIndex);
            g_active_msmt->curStepData.StepId = cfg->Step[StepCount].StepId;

            memcpy(g_active_msmt->curStepData.DestMac, cfg->Step[StepCount].DestMac, sizeof(mac_address_t));

            wifi_util_dbg_print(WIFI_BLASTER,"%s:%d copied mac address " MAC_FMT " to current step info\n", __func__, __LINE__,
                MAC_ARG(g_active_msmt->curStepData.DestMac));

            wifi_util_error_print(WIFI_BLASTER, "Value of cfg->Step[StepCount].DestMac is %s\n", cfg->Step[StepCount].DestMac);

            if (isVapEnabled(apIndex) != 0) {
                wifi_util_error_print(WIFI_BLASTER, "ERROR running wifiblaster: Init Failed\n" );
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }
            bmac[0] = g_active_msmt->curStepData.DestMac[0]; bmac[1] = g_active_msmt->curStepData.DestMac[1];
            bmac[2] = g_active_msmt->curStepData.DestMac[2]; bmac[3] = g_active_msmt->curStepData.DestMac[3];
            bmac[4] = g_active_msmt->curStepData.DestMac[4]; bmac[5] = g_active_msmt->curStepData.DestMac[5];

            wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);

            if (is_blaster_device_associated(apIndex, bmac, NULL) == false &&
                is_blaster_device_associated_aap_link(bmac, &g_active_msmt->curStepData) == false) {

                if (g_wifi_ctrl->network_mode == rdk_dev_mode_type_ext) {

                    snprintf(msg, sizeof(msg), "The MAC is disconnected in traffic gen");
                    active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[StepCount], msg, ACTIVE_MSMT_STATUS_NO_CLIENT);

                    SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
                } else {
                    pthread_mutex_unlock(&g_active_msmt->lock);
                    process_active_msmt_diagnostics(apIndex);
                    stream_client_msmt_data(true);
                    pthread_mutex_lock(&g_active_msmt->lock);
                }

                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d no need to start pktgen for offline client: %s\n" ,__FUNCTION__, __LINE__, (char *)g_active_msmt->curStepData.DestMac);
                active_msmt_set_step_status(__func__, StepCount, ACTIVE_MSMT_STEP_INVALID);
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }
            /* radio/pktgen path (macStr snprintf, pkt_gen_blast_client) not reached in this harness */
        }
        pthread_mutex_unlock(&g_active_msmt->lock);
    }
}

/*
 * HANDLER: sample_blaster
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). No fixes. Local arrays:
 *   - bmac[6]   <- fixed indices 0..5 from curStepData.DestMac
 *   - msg[256]  <- snprintf(msg, sizeof(msg), "...") in the ext-mode
 *                  "not found in provider stats" branch (bounded)
 * (The CONFIG_IEEE80211BE / _PP203X_ blocks are compiled out, as upstream.)
 *
 * This harness drives the radio_index == RETURN_ERR offline branch, which
 * exercises bmac and the frameCountSample / Operating_standard writes and
 * returns before the msg branch. msg[256] is still redirected and poisoned.
 *
 * Redirect: snprintf() -> sb_snprintf(): real vsnprintf on a runner slot of
 * the SAME size (256 -> sb_slot_msg; the OPER_BUFFER_LEN Operating_* writes
 * go to sb_slot_oper), then copied back. The RUNNER poisons sb_slot_msg past
 * 256, the provider_response / stand-ins past their sizes, and the sample
 * arrays past their counts. bmac/msg are also ASan-stack-guarded.
 *
 * Scaffolding (NOT the function under test): every external helper is a
 * file-local stub; get_radio_index_for_vap_index() returns RETURN_ERR to
 * select the offline path.
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
#define WIFI_APPS    0
#define RETURN_ERR  -1
#define rdk_dev_mode_type_ext 1
#define wifi_app_inst_blaster 0x4
#define OPER_BUFFER_LEN 64


static void sb_print(int module, const char *fmt, ...)
{ char sc[1024]; va_list ap; (void)module; va_start(ap, fmt); vsnprintf(sc, sizeof(sc), fmt, ap); va_end(ap); }
#define wifi_util_dbg_print    sb_print
#define wifi_util_error_print  sb_print

static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)sb_wctrl_buf; }
static wifi_mgr_t *get_wifimgr_obj(void)  { return (wifi_mgr_t *)sb_wmgr_buf; }
static wifi_actvie_msmt_t *get_wifi_blaster(void) { return (wifi_actvie_msmt_t *)sb_mgr_buf; }
static unsigned int *get_sample_count(void) { return &sb_sample_count; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return sb_app; }
static int  get_radio_index_for_vap_index(void *prop, int idx) { (void)prop; (void)idx; return sb_radio_err ? RETURN_ERR : 0; }
static unsigned int GetActiveMsmtNumberOfSamples(void) { return sb_num_samples; }
static bool is_blaster_device_associated(int ap, unsigned char *mac, bool *mlo) { (void)ap;(void)mac;(void)mlo; return false; }
static bool is_blaster_device_associated_aap_link(unsigned char *mac, void *step) { (void)mac;(void)step; return false; }
static void SetActiveMsmtStatus(const char *f, active_msmt_status_t s) { (void)f; (void)s; }
static void active_msmt_set_status_desc(const char *f, unsigned char *p, unsigned int id, unsigned char *dm, char *msg)
{ (void)f;(void)p;(void)id;(void)dm; snprintf(sb_last_err, sizeof(sb_last_err), "%s", msg); sb_statusdesc_calls++; }
static void active_msmt_log_message(int level, const char *fmt, ...) { (void)level; (void)fmt; }
static void sample_done_notify(void) { sb_done_notify++; }
static unsigned long getCurrentTimeInMicroSeconds(void) { return 1000; }
static void calculate_throughput(int mld_link_num) { (void)mld_link_num; sb_calc_throughput++; }

/* redirect: msg[256] and Operating_* writes into runner slots of the same size */
static int sb_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    char *slot = (sz == SB_MSG_SZ) ? sb_slot_msg : sb_slot_oper;
    size_t cap = (sz == SB_MSG_SZ) ? SB_MSG_SZ : SB_OPER_SZ;
    if (sz > cap) sz = cap;
    int r; va_list ap;
    memset(slot, 0, sz);
    va_start(ap, fmt); r = vsnprintf(slot, sz, fmt, ap); va_end(ap);
    memcpy(out, slot, sz);
    if (sz == SB_MSG_SZ) sb_msg_len = strnlen(slot, sz);
    return r;
}
#define snprintf(o, n, ...)  sb_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
void sample_blaster(wifi_provider_response_t *provider_response)
{
    mac_address_t bmac;
    wifi_associated_dev3_t *dev_conn = NULL;
    sta_data_t *assoc_stats = NULL;
    bool is_associated = false;
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    char msg[256] = {};
    assoc_stats = (sta_data_t *) provider_response->stat_pointer;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_step_t *step = &g_active_msmt->curStepData;
    unsigned int *SampleCount = get_sample_count();
    unsigned int count = 0;
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        sample_done_notify();
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        sample_done_notify();
        return;
    }

    int index = g_active_msmt->curStepData.ApIndex;
    int mld_link_num = -1;
    int mld_link_idx = 0;
    while((mld_link_num < MAX_NUM_RADIOS - 2) && (g_active_msmt->curStepData.mldApIndex[mld_link_num+1] >= 0))
    {
        if (provider_response->args.vap_index == (unsigned int)g_active_msmt->curStepData.mldApIndex[mld_link_num+1]) {
            index = provider_response->args.vap_index;
            mld_link_idx = mld_link_num+2;
        }
        mld_link_num++;
    }
    if (g_active_msmt->curStepData.isMLO)
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Received MLO link stats response from AP %d\n", __func__, __LINE__, index);

    int radio_index = get_radio_index_for_vap_index(&(get_wifimgr_obj())->hal_cap.wifi_prop, index);
#if defined (_PP203X_PRODUCT_REQ_) || defined (_GREXT02ACTS_PRODUCT_REQ_)
    wifi_radio_operationParam_t* radioOperation = NULL;
    radioOperation = getRadioOperationParam(radio_index);
#endif //_PP203X_PRODUCT_REQ_ , _GREXT02ACTS_PRODUCT_REQ_

    bmac[0] = g_active_msmt->curStepData.DestMac[0]; bmac[1] = g_active_msmt->curStepData.DestMac[1];
    bmac[2] = g_active_msmt->curStepData.DestMac[2]; bmac[3] = g_active_msmt->curStepData.DestMac[3];
    bmac[4] = g_active_msmt->curStepData.DestMac[4]; bmac[5] = g_active_msmt->curStepData.DestMac[5];

    wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
    wifi_util_error_print(WIFI_BLASTER, "%s: sample count is %d and total number of sampls given %d\n", __func__, *SampleCount, GetActiveMsmtNumberOfSamples());

    /* sampling */

if ( *SampleCount <= (GetActiveMsmtNumberOfSamples())) {

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s : %d WIFI_HAL enabled, calling wifi_getApAssociatedClientDiagnosticResult\n",__func__,__LINE__);

    if (radio_index != RETURN_ERR) {
        wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
        wifi_util_error_print(WIFI_BLASTER, "%s: provider_response->stat_array_size %u\n", __func__, provider_response->stat_array_size);
        for (count = 0; count < provider_response->stat_array_size; count++) {
            wifi_util_error_print(WIFI_BLASTER, "%s: provider mac is %02x:%02x:%02x:%02x:%02x:%02x \n", __func__, assoc_stats[count].sta_mac[0], assoc_stats[count].sta_mac[1],
                assoc_stats[count].sta_mac[2], assoc_stats[count].sta_mac[3], assoc_stats[count].sta_mac[4], assoc_stats[count].sta_mac[5]);
            if (!memcmp(bmac, assoc_stats[count].sta_mac, sizeof(mac_address_t))) {
                is_associated = true;
                dev_conn = &assoc_stats[count].dev_stats;
                wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x found \n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
                break;
            }
        }
        if(is_associated){
            is_associated = false;

            if (wifi_app->data.u.blaster.frameCountSample == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "%s:%d Framecount sample is NULL \n", __func__, __LINE__);
                sample_done_notify();
                return;
            }

            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs = ((getCurrentTimeInMicroSeconds () - wifi_app->data.u.blaster.blaster_start) / 1000);
            active_msmt_log_message(BLASTER_DEBUG_LOG, "PKTGEN_WAIT_IN_MS duration : %lu and value of getcurrent time is %lu and value of blaster_start is %lu \n", ((getCurrentTimeInMicroSeconds () - wifi_app->data.u.blaster.blaster_start)/1000), getCurrentTimeInMicroSeconds (), wifi_app->data.u.blaster.blaster_start);
            if (!g_active_msmt->curStepData.isMLO || (g_active_msmt->curStepData.isMLO && assoc_stats[count].assoc_link)) {
                g_active_msmt->active_msmt_data[*SampleCount].rssi = dev_conn->cli_RSSI;
                g_active_msmt->active_msmt_data[*SampleCount].TxPhyRate = dev_conn->cli_LastDataDownlinkRate;
                g_active_msmt->active_msmt_data[*SampleCount].RxPhyRate = dev_conn->cli_LastDataUplinkRate;
                g_active_msmt->active_msmt_data[*SampleCount].SNR = dev_conn->cli_SNR;
                g_active_msmt->active_msmt_data[*SampleCount].ReTransmission = dev_conn->cli_Retransmissions;
                g_active_msmt->active_msmt_data[*SampleCount].MaxTxRate = dev_conn->cli_MaxDownlinkRate;
                g_active_msmt->active_msmt_data[*SampleCount].MaxRxRate = dev_conn->cli_MaxUplinkRate;
#if defined (_PP203X_PRODUCT_REQ_) || defined (_GREXT02ACTS_PRODUCT_REQ_)
                if (radioOperation != NULL) {
                    convert_channel_width_to_str(radioOperation->channelWidth, g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth, OPER_BUFFER_LEN);
                    convert_variant_to_str(radioOperation->variant, g_active_msmt->active_msmt_data[*SampleCount].Operating_standard, OPER_BUFFER_LEN);
                }
#else
                if (strstr(dev_conn->cli_OperatingStandard, "802.11") != NULL) {
                    sscanf(dev_conn->cli_OperatingStandard, "802.11%2s", g_active_msmt->active_msmt_data[*SampleCount].Operating_standard);
                } else {
                    snprintf(g_active_msmt->active_msmt_data[*SampleCount].Operating_standard, OPER_BUFFER_LEN, dev_conn->cli_OperatingStandard);
                }
                snprintf(g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth, OPER_BUFFER_LEN, dev_conn->cli_OperatingChannelBandwidth);
#endif //_PP203X_PRODUCT_REQ_ , _GREXT02ACTS_PRODUCT_REQ_
            }

            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentAck[mld_link_idx] = dev_conn->cli_DataFramesSentAck;
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentTotal[mld_link_idx] = dev_conn->cli_PacketsSent + dev_conn->cli_DataFramesSentNoAck;

            wifi_util_dbg_print(WIFI_BLASTER,"samplecount[%d] : PacketsSentAck[%lu] PacketsSentTotal[%lu]"
                    " WaitAndLatencyInMs[%d ms] RSSI[%d] TxRate[%lu Mbps] RxRate[%lu Mbps] SNR[%d]"
                    "chanbw [%s] standard [%s] MaxTxRate[%d] MaxRxRate[%d]\n",
                    *SampleCount, dev_conn->cli_DataFramesSentAck, (dev_conn->cli_PacketsSent + dev_conn->cli_DataFramesSentNoAck),
                    (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs, dev_conn->cli_RSSI, dev_conn->cli_LastDataDownlinkRate, dev_conn->cli_LastDataUplinkRate, dev_conn->cli_SNR,g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth ,g_active_msmt->active_msmt_data[*SampleCount].Operating_standard,g_active_msmt->active_msmt_data[*SampleCount].MaxTxRate, g_active_msmt->active_msmt_data[*SampleCount].MaxRxRate);
            } else {

                if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                    active_msmt_status_t status;

                    if (is_blaster_device_associated(index, bmac, NULL) == false &&
                        is_blaster_device_associated_aap_link(bmac, &g_active_msmt->curStepData) == false) {
                        snprintf(msg, sizeof(msg), "The MAC is disconnected");
                        status = ACTIVE_MSMT_STATUS_NO_CLIENT;
                    }
                    else {
                        snprintf(msg, sizeof(msg), "Failed to fill in client stats");
                        status = ACTIVE_MSMT_STATUS_FAILED;
                    }

                    SetActiveMsmtStatus(__func__, status);
                    active_msmt_set_status_desc(__func__, g_active_msmt->active_msmt.PlanId, step->StepId, step->DestMac, msg);
                }

                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s : %d Unable to get provider response for : %s\n",__func__,__LINE__,g_active_msmt->curStepData.DestMac);
                (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentTotal[mld_link_idx] = 0;
                (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentAck[mld_link_idx] = 0;
                (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs = 0;
                sample_done_notify();
                return;
            }
        } else {
            active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d radio_index is invalid. So, client is treated as offline\n",__func__, __LINE__);
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentTotal[mld_link_idx] = 0;
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentAck[mld_link_idx] = 0;
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs = 0;
            strncpy(g_active_msmt->active_msmt_data[*SampleCount].Operating_standard, "NULL",OPER_BUFFER_LEN);
            strncpy(g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth, "NULL",OPER_BUFFER_LEN);
            sample_done_notify();
            return;
        }
        if (!g_active_msmt->curStepData.isMLO)
        {
            wifi_app->data.u.blaster.blaster_start = getCurrentTimeInMicroSeconds ();
            *SampleCount += 1;
        }
        else if (mld_link_num < 0 || index == g_active_msmt->curStepData.mldApIndex[mld_link_num])
        {
            wifi_app->data.u.blaster.blaster_start = getCurrentTimeInMicroSeconds ();
            *SampleCount += 1;
        }
}
    if (dev_conn != NULL){
        //free(dev_conn);
        dev_conn = NULL;
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Sample count value = %d\n", __func__, __LINE__, *SampleCount);
    if (*SampleCount == g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples + 1){
        *SampleCount = 0;
        calculate_throughput(mld_link_num+1);
        sample_done_notify();
    }
}

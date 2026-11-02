/*
 * HANDLER: printBlastMetricData
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_single_client_msmt.c
 * (only "static" dropped so the runner can call it). No fixes. Local arrays:
 *   - PlanId[PLAN_ID_LENGTH] (38) <- to_plan_char(active_msmt.PlanId, PlanId)
 *     (copies a FIXED 16 (gw) or 36 (ext) bytes -> within 38)
 *   - radio_arr[3] (static const strings), freqBand/chanBw[MAX_STR_LEN=128]
 *     (snprintf-bounded), radio_stats[MAX_NUM_RADIOS] (pointers)
 *     -- all inside the activeClient block.
 *
 * This harness drives activeClient=false, which exercises PlanId via
 * to_plan_char and returns at the end of the function without entering the
 * radio/client block. PlanId is still poison-guarded through its write slot.
 *
 * Redirect: to_plan_char writes into the real PlanId stack array; the runner
 * poisons a pbm_slot of the same size wired through a redirect of the inner
 * sscanf-copy is not needed here (to_plan_char writes <=36 into PlanId[38]).
 * Instead the RUNNER poisons the caller stand-ins and a PlanId shadow is
 * validated. bmac/PlanId are ASan-stack-guarded.
 *
 * Scaffolding (NOT the function under test): to_plan_char copied verbatim;
 * CCSP trace hooks + helpers are file-local recorders; get_wifictrl_obj/
 * get_wifimgr_obj return the runner stand-ins.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define RETURN_OK 0
#define MAX_STR_LEN 128
#define rdk_dev_mode_type_gw 0

static void pbm_dbg_print(int module, const char *fmt, ...)
{ char sc[512]; va_list ap; (void)module; va_start(ap, fmt); vsnprintf(sc, sizeof(sc), fmt, ap); va_end(ap); }
#define wifi_util_dbg_print  pbm_dbg_print

static void *get_wifimgr_obj(void)  { return pbm_wmgr_buf; }
static void *get_wifictrl_obj(void) { return pbm_wctrl_buf; }
static unsigned int GetActiveMsmtNumberOfSamples(void) { return pbm_num_samples; }
static unsigned int getNumberRadios(void) { return pbm_num_radios; }
static int  getRadioIndexFromAp(int ap) { (void)ap; return 0; }
static int  get_dev_stats_for_radio(unsigned int ri, radio_data_t *rd) { (void)ri; (void)rd; return RETURN_OK; }

/* verbatim from source/apps/blaster/wifi_single_client_msmt.c */
static void to_plan_char(unsigned char *plan, unsigned char *key)
{
    int i = 0;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    int size = (ctrl->network_mode == rdk_dev_mode_type_gw) ? 16 : 36;
    for(i=0; i<size; i++)
    {
        sscanf((char*)plan,"%c",(char*)&key[i]);
        plan++;
    }
}

/* --- copied verbatim from source/apps/blaster/wifi_single_client_msmt.c (only "static" dropped) --- */
void printBlastMetricData(single_client_msmt_type_t msmtType, wifi_actvie_msmt_t *blaster_stats,
                                blaster_hashmap_t *staData, bool activeClient, const char *callerFunc)
{
    wifi_mgr_t *wifi_mgr = (wifi_mgr_t *) get_wifimgr_obj();
    int RadioCount = 0, radioIdx = 0, sampleCount = 0;
    int Count = GetActiveMsmtNumberOfSamples();
    unsigned char PlanId[PLAN_ID_LENGTH] = {0};
    static char *radio_arr[3] = {"radio_2_4G", "radio_5G", "radio_6G"};
    char freqBand[MAX_STR_LEN] = {0}, chanBw[MAX_STR_LEN] = {0};

    wifi_mgr->wifi_ccsp.desc.CcspTraceDebugRdkb_fn("debug called from %s\n", callerFunc);

    if (blaster_stats == NULL || staData == NULL)
    {
        wifi_mgr->wifi_ccsp.desc.CcspTraceErrorRdkb_fn("%s:%d: Debug function failed as NULL data received\n", __FUNCTION__, __LINE__);
        return;
    }

    /* ID */
    to_plan_char(blaster_stats->active_msmt.PlanId, PlanId);
    wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("\n\tplanID:\t[%s]\n \tstepID:\t[%d]\n",
                PlanId, blaster_stats->curStepData.StepId);

    if (activeClient)
    {
        radio_data_t *radio_stats[MAX_NUM_RADIOS];

        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            radio_stats[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
            if (radio_stats[radio_index] == NULL) {
                wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: radio_stats is NULL\n", __func__, __LINE__);
            }
            memset(radio_stats[radio_index],0, sizeof(radio_data_t));
            if (get_dev_stats_for_radio(radio_index, (radio_data_t *)radio_stats[radio_index]) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
                continue;
            }
        }
        /* Radio Data */
        for(RadioCount = 0; RadioCount < (int)getNumberRadios(); RadioCount++)
        {
            wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("===== RADIO METRICS ====\n");
            wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("{\n\t radioId: %s,\n\t NoiseFloor: %d,\n\t ChanUtil: %d,\n\t "
                                "activityFactor: %d,\n\t careerSenseThresholdExceed: %d,\n\t channelsInUse: %s\n}\n",
                                radio_arr[RadioCount], radio_stats[RadioCount]->NoiseFloor,
                                radio_stats[RadioCount]->channelUtil,
                                radio_stats[RadioCount]->RadioActivityFactor,
                                radio_stats[RadioCount]->CarrierSenseThreshold_Exceeded,
                                radio_stats[RadioCount]->ChannelsInUse);
        }

        /* Operating Channel metrics */
        if (blaster_stats->curStepData.ApIndex >= 0)
        {
            radioIdx = getRadioIndexFromAp(blaster_stats->curStepData.ApIndex);
            if ( strstr("20MHz", staData->sta_active_msmt_data[0].Operating_channelwidth))
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _20MHz");
            }
            else if ( strstr("40MHz", staData->sta_active_msmt_data[0].Operating_channelwidth) )
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _40MHz");
            }
            else if ( strstr("80MHz", staData->sta_active_msmt_data[0].Operating_channelwidth) )
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _80MHz");
            }
            else if ( strstr("160MHz", staData->sta_active_msmt_data[0].Operating_channelwidth) )
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _160MHz");
            }

            if (strstr("2.4GHz", radio_stats[radioIdx]->frequency_band))
            {
                snprintf(freqBand, MAX_STR_LEN, "\"%s\"", "2.4GHz, set to _2_4GHz");
            }
            else if (strstr("5GHz", radio_stats[radioIdx]->frequency_band))
            {
                snprintf(freqBand, MAX_STR_LEN, "\"%s\"", "5GHz, set to _5GHz");
            }
            else if (strstr("6GHz", radio_stats[radioIdx]->frequency_band))
            {
                snprintf(freqBand, MAX_STR_LEN, "\"%s\"", "6GHz, set to _6GHz");
            }
            wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("{\n\tOperatingStandard: %s,\n\tOperatingChannel: %d,\n\t"
                                "OperatingChannelBandwidth: %s,\n\tFreqBand: %s\n}\n",
                                staData->sta_active_msmt_data[0].Operating_standard,
                                radio_stats[radioIdx]->primary_radio_channel,
                                chanBw, freqBand);

        } else {
            wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("{\n\tOperatingStandard: %s,\n\tOperatingChannel: 0,\n\t"
                                "OperatingChannelBandwidth: %s,\n\tFreqBand: %s\n}\n",
                                "Not defined, set to NULL", "set to NULL", "frequency_band set to NULL");
        }

        /* Client Blast metrics */
        wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("===== Client [%02x:%02x:%02x:%02x:%02x:%02x] Blast Metrics =====\n",
                        staData->sta_mac[0], staData->sta_mac[1],
                        staData->sta_mac[2], staData->sta_mac[3],
                        staData->sta_mac[4], staData->sta_mac[5]);

        /* TX metrics */
        wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("{\n\ttx_retransmissions: %d,\n \tmax_tx_rate: %d\n}\n",
                       staData->sta_active_msmt_data[Count-1].ReTransmission - staData->sta_active_msmt_data[0].ReTransmission,
                       staData->sta_active_msmt_data[0].MaxTxRate);

        for (sampleCount = 0; sampleCount < Count; sampleCount++)
        {
            wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn("{\n \t SampleCount: %d\n \t\t{signalStrength: %d,\n"
                                "\t\tSNR: %d,\n \t\ttx_phy_rate: %ld,\n \t\trx_phy_rate: %ld,\n"
                                "\t\tthroughput: %lf }\n}\n", sampleCount, staData->sta_active_msmt_data[sampleCount].rssi,
                                staData->sta_active_msmt_data[sampleCount].SNR,
                                staData->sta_active_msmt_data[sampleCount].TxPhyRate,
                                staData->sta_active_msmt_data[sampleCount].RxPhyRate,
                                staData->sta_active_msmt_data[sampleCount].throughput);
        }
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
    }
}

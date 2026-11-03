/*
 * HANDLER: process_instant_msmt_start
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c. Local
 * array:
 *   - char event_buff[16] = {0} : strncpy(event_buff, "inst_msmt started",
 *     sizeof(event_buff)-1) copies 15 chars; byte [15] stays 0 (zero-init), so
 *     the buffer is NUL-terminated and strlen() == 15 < 16. SAFE.
 *   (Same latent under-copy note as the stop twin: strncpy(data->u.msg.data,
 *    "...", sizeof(MAX_FRAME_SZ)-1) copies only 3 bytes -- not an overflow.)
 *
 * Scaffolding (NOT under test): push_event_to_ctrl_queue /
 * push_event_to_monitor_queue / push_harvester_config_event_to_monitor_queue
 * are stubbed; the ctrl-queue stub copies the pushed bytes into pist_sink
 * (whose tail the runner poisons). Driven by the pist_* globals + g_harvester_module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define WIFI_HARVESTER 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#define wifi_event_type_command         1
#define wifi_event_type_start_inst_msmt 22
#define wifi_event_monitor_start_inst_msmt 23
#define mon_stats_request_state_start   1

/* --- scaffolding stubs driven by pist_* globals --- */
static void push_harvester_config_event_to_monitor_queue(int state) { (void)state; pist_cfg_push++; }
static void push_event_to_ctrl_queue(void *buf, unsigned int len, int t1, int t2, void *p)
{
    (void)t1; (void)t2; (void)p;
    if (len > PIST_SINK_SZ) len = PIST_SINK_SZ;
    memcpy(pist_sink, buf, len);          /* trips if len exceeds the poisoned region */
    pist_ctrl_len = (int)len;
    pist_ctrl_push++;
}
static void push_event_to_monitor_queue(void *data, int ev, void *p) { (void)data; (void)ev; (void)p; pist_mon_push++; }

/* ================= VERBATIM from wifi_harvester.c ================= */
void process_instant_msmt_start()
{
    wifi_monitor_data_t *data;
    data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return;
    }

    memset(data, 0, sizeof(wifi_monitor_data_t));
    char event_buff[16] = {0};
    g_harvester_module.poll_period = g_harvester_module.instantPollPeriod;
    g_harvester_module.inst_msmt.active = g_harvester_module.instntMsmtenable;

    if ((g_harvester_module.instantDefOverrideTTL == 0) || (g_harvester_module.instantPollPeriod == 0))
        g_harvester_module.maxCount = 0;
    else
        g_harvester_module.maxCount = g_harvester_module.instantDefOverrideTTL/g_harvester_module.instantPollPeriod;

    g_harvester_module.count = 0;
    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: count:%d, maxCount:%d, TTL:%d, poll:%d\n",__func__, __LINE__,
            g_harvester_module.count, g_harvester_module.maxCount, g_harvester_module.instantDefOverrideTTL, g_harvester_module.instantPollPeriod);
    strncpy((char *)data->u.msg.data, "inst_msmt started", sizeof(MAX_FRAME_SZ)-1);
    strncpy(event_buff, "inst_msmt started", sizeof(event_buff)-1);
    push_event_to_ctrl_queue(event_buff, (strlen(event_buff) +1), wifi_event_type_command, wifi_event_type_start_inst_msmt, NULL);
    push_event_to_monitor_queue(data, wifi_event_monitor_start_inst_msmt, NULL);
    push_harvester_config_event_to_monitor_queue(mon_stats_request_state_start);
    g_harvester_module.inst_msmt_id += 1 ;
    if(data != NULL){
        free(data);
        data = NULL;
    }
}

/*
 * HANDLER: process_instant_msmt_stop
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c. Local
 * array:
 *   - char event_buff[16] = {0} : strncpy(event_buff, "inst_msmt completed",
 *     sizeof(event_buff)-1) copies 15 chars; byte [15] stays 0 (zero-init), so
 *     the buffer is NUL-terminated and strlen() == 15 < 16. SAFE.
 *
 * (Observation, not an array OOB: strncpy(data->u.msg.data, "...",
 *  sizeof(MAX_FRAME_SZ)-1) uses sizeof(int)-1 == 3, so data->u.msg.data gets
 *  only "ins" -- a latent under-copy/truncation bug, no overflow.)
 *
 * Scaffolding (NOT under test): getNumberRadios /
 * push_harvester_config_event_to_monitor_queue / push_event_to_ctrl_queue /
 * push_event_to_monitor_queue are stubbed; push_event_to_ctrl_queue copies the
 * pushed bytes into pims_sink (whose tail the runner poisons). Driven by the
 * pims_* globals + g_harvester_module.
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
#define DEFAULT_INSTANT_POLL_TIME 5
#define wifi_event_type_command        1
#define wifi_event_type_stop_inst_msmt 20
#define wifi_event_monitor_stop_inst_msmt 21
#define mon_stats_request_state_stop   2

/* --- scaffolding stubs driven by pims_* globals --- */
static unsigned int getNumberRadios(void) { return (unsigned int)pims_num_radios; }
static void push_harvester_config_event_to_monitor_queue(int state) { (void)state; pims_cfg_push++; }
static void push_event_to_ctrl_queue(void *buf, unsigned int len, int t1, int t2, void *p)
{
    (void)t1; (void)t2; (void)p;
    if (len > PIMS_SINK_SZ) len = PIMS_SINK_SZ;
    memcpy(pims_sink, buf, len);          /* trips if len exceeds the poisoned region */
    pims_ctrl_len = (int)len;
    pims_ctrl_push++;
}
static void push_event_to_monitor_queue(void *data, int ev, void *p) { (void)data; (void)ev; (void)p; pims_mon_push++; }

/* ================= VERBATIM from wifi_harvester.c ================= */
void process_instant_msmt_stop()
{
    g_harvester_module.inst_msmt.active = false;
    g_harvester_module.poll_period = DEFAULT_INSTANT_POLL_TIME;
    g_harvester_module.maxCount = 0;
    g_harvester_module.count = 0;
    wifi_util_dbg_print(WIFI_HARVESTER,"%s %d Entering \n",__FUNCTION__, __LINE__);

    if (g_harvester_module.inst_msmt_id != 0) {
        char event_buff[16] = {0};
        wifi_monitor_data_t *data;
        data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
        if (data == NULL) {
            wifi_util_error_print(WIFI_HARVESTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
            return;
        }

        memset(data, 0, sizeof(wifi_monitor_data_t));
        push_harvester_config_event_to_monitor_queue(mon_stats_request_state_stop);

        strncpy((char *) data->u.msg.data, "inst_msmt completed", sizeof(MAX_FRAME_SZ)-1);
        strncpy(event_buff, "inst_msmt completed", sizeof(event_buff)-1);

        push_event_to_ctrl_queue(event_buff, (strlen(event_buff) +1), wifi_event_type_command, wifi_event_type_stop_inst_msmt, NULL);
        push_event_to_monitor_queue(data, wifi_event_monitor_stop_inst_msmt, NULL);
        g_harvester_module.inst_msmt_id = 0;

        if (data != NULL) {
            free(data);
            data = NULL;
        }
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if (g_harvester_module.radio_data[radio_index] != NULL) {
                free(g_harvester_module.radio_data[radio_index]);
                g_harvester_module.radio_data[radio_index] = NULL;
            }
        }
    }
}

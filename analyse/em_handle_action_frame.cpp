/*
 * HANDLER: em_handle_action_frame
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (only "static"
 * dropped). Local arrays:
 *   - wifi_hal_rrm_report_t rep : fixed struct.
 *   - mac_address_t mac_addr    : memcpy(mac_addr, mgmt->sa, ETH_ALEN=6) -- a
 *     fixed 6-byte copy into a 6-byte array.
 * NULL arg / NULL ctrl / short frame (len <= 32) are rejected before the copy.
 * No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / wifi_hal_parse_rm_beaon_report
 * are stubbed; em_process_beacon_rep is #define-redirected to a local stub
 * (the real symbol lives in its own TU). Driven by the ehaf_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#define WIFI_EM 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#define WLAN_RRM_RADIO_MEASUREMENT_REPORT 5

/* --- scaffolding stubs driven by ehaf_* globals --- */
static wifi_ctrl_t *get_wifictrl_obj(void) { return ehaf_ctrl_null ? NULL : (wifi_ctrl_t *)ehaf_ctrl_buf; }
static int wifi_hal_parse_rm_beaon_report(int ap_index, const struct ieee80211_mgmt *mgmt, size_t len, wifi_hal_rrm_report_t *rep)
{
    (void)ap_index; (void)mgmt; (void)len;
    if (ehaf_parse_fail) return RETURN_ERR;
    rep->dialog_token = 5;
    rep->size = 2;
    return RETURN_OK;
}
static int ehaf_process(mac_address_t sta, wifi_hal_rrm_report_t *rep, wifi_app_t *app,
    const struct ieee80211_mgmt *mgmt, size_t len, int ap_index)
{
    (void)sta; (void)rep; (void)app; (void)mgmt; (void)len; (void)ap_index;
    ehaf_process_calls++;
    return RETURN_OK;
}
#define em_process_beacon_rep(a, b, c, d, e, f)  ehaf_process((a), (b), (c), (d), (e), (f))

/* ================= VERBATIM from wifi_em.c (static dropped) ================= */
int em_handle_action_frame(wifi_app_t *apps, void *arg)
{
    frame_data_t *mgmt_frame = (frame_data_t *)arg;
    wifi_hal_rrm_report_t rep;
    mac_address_t mac_addr;

    if (mgmt_frame == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NULL arg\n", __func__, __LINE__);
        return -1;
    }

    const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)mgmt_frame->data;
    size_t len = mgmt_frame->frame.len;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NULL ctrl\n", __func__, __LINE__);
        return -1;
    }

    if (mgmt == NULL || len <= 32) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Invalid Beacon Report Not processing\n", __func__,
            __LINE__);
        return -1;
    }

    memcpy(mac_addr, mgmt->sa, ETH_ALEN);
    wifi_util_dbg_print(WIFI_EM, "%s:%d: rrm.action:%d, mode:%d and len:%zu\n", __func__, __LINE__,
        mgmt->u.action.u.rrm.action, ctrl->network_mode, len);

    switch (mgmt->u.action.u.rrm.action) {
    case WLAN_RRM_RADIO_MEASUREMENT_REPORT:
        if (ctrl->network_mode == rdk_dev_mode_type_gw ||
            ctrl->network_mode == rdk_dev_mode_type_em_colocated_node ||
            ctrl->network_mode == rdk_dev_mode_type_em_node) {
            if (wifi_hal_parse_rm_beaon_report(mgmt_frame->frame.ap_index, mgmt, len, &rep) ==
                RETURN_OK) {
                em_process_beacon_rep(mac_addr, &rep, apps, mgmt, len, mgmt_frame->frame.ap_index);
            }
        }
        break;
    default:
        wifi_util_dbg_print(WIFI_EM, "%s:%d: unhandled RRM action type %d\n", __func__, __LINE__,
            mgmt->u.action.u.rrm.action);
        break;
    }
    return 0;
}

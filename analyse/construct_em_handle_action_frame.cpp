/*
 * TEST CASES / CONSTRUCTOR: construct_em_handle_action_frame
 *
 * arg (a frame_data_t) lives at ehaf_arg_buf; an ieee80211_mgmt is overlaid on
 * its data[] with sa = 30:..:35 and the RRM action byte set. The wifi_ctrl
 * stand-in is at ehaf_ctrl_buf (network_mode per case). ehaf_* globals steer
 * get_wifictrl_obj / wifi_hal_parse_rm_beaon_report.
 *
 * Cases: rrm_report_gw / rrm_report_node (action=REPORT + eligible mode + parse
 * ok -> em_process_beacon_rep called), wrong_action, wrong_mode, parse_fail
 * (no process call), null_arg / ctrl_null / short_len (-> -1).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define EHAF_RRM_REPORT 5

alignas(16) char ehaf_ctrl_buf[sizeof(wifi_ctrl_t) + EHAF_PAD];
alignas(16) char ehaf_arg_buf[sizeof(frame_data_t) + EHAF_PAD];
int ehaf_ctrl_null, ehaf_parse_fail, ehaf_process_calls;

em_ehaf_test_case_t em_handle_action_frame_suite[] = {
    /* name           arg_null ctrl_null short_len action mode               parse_fail want_rc want_proc */
    { "rrm_report_gw",   0,     0,        0,        5,     rdk_dev_mode_type_gw,              0,  0,  1 },
    { "rrm_report_node", 0,     0,        0,        5,     rdk_dev_mode_type_em_node,         0,  0,  1 },
    { "wrong_action",    0,     0,        0,       99,     rdk_dev_mode_type_gw,              0,  0,  0 },
    { "wrong_mode",      0,     0,        0,        5,     rdk_dev_mode_type_ext,             0,  0,  0 },
    { "parse_fail",      0,     0,        0,        5,     rdk_dev_mode_type_gw,              1,  0,  0 },
    { "null_arg",        1,     0,        0,        5,     rdk_dev_mode_type_gw,              0, -1,  0 },
    { "ctrl_null",       0,     1,        0,        5,     rdk_dev_mode_type_gw,              0, -1,  0 },
    { "short_len",       0,     0,        1,        5,     rdk_dev_mode_type_gw,              0, -1,  0 },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_handle_action_frame_input(const em_ehaf_test_case_t *tc)
{
    memset(ehaf_ctrl_buf, 0, sizeof(ehaf_ctrl_buf));
    memset(ehaf_arg_buf, 0, sizeof(ehaf_arg_buf));

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)ehaf_ctrl_buf;
    ctrl->network_mode = tc->mode;

    frame_data_t *fd = (frame_data_t *)ehaf_arg_buf;
    fd->frame.ap_index = 3;
    fd->frame.len = tc->short_len ? 20 : 64;

    /* overlay an 802.11 mgmt frame in data[] */
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)fd->data;
    unsigned char sa[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    memcpy(mgmt->sa, sa, 6);
    mgmt->u.action.category = 5;              /* WLAN_ACTION_RADIO_MEASUREMENT */
    mgmt->u.action.u.rrm.action = (unsigned char)tc->action;

    ehaf_ctrl_null  = tc->ctrl_null;
    ehaf_parse_fail = tc->parse_fail;
    ehaf_process_calls = 0;
}

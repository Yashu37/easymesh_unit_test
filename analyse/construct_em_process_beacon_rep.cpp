/*
 * TEST CASES / CONSTRUCTOR: construct_em_process_beacon_rep
 *
 * The 802.11 frame lives at epbr_mgmt_buf (a wide static buffer); rrm.variable
 * sits at min_len = IEEE80211_HDRLEN + 1 + sizeof(rrm). The rep header is at
 * epbr_rep_buf; the app (with ctrl->handle) at epbr_app_buf/epbr_appctrl_buf.
 * The runner poisons the frame tail past `len`.
 *
 * Cases: ok_50 (data_len 50 -> publish), short_frame (len <= min_len -> -1),
 * data_too_big (data_len > MAX_FRAME_SZ -> -1), publish_fail.
 * epbr_len/epbr_datalen are set so the runner can pass the right len.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char epbr_mgmt_buf[IEEE80211_HDRLEN + 1 + 8 + MAX_FRAME_SZ + 128 + EPBR_PAD];
alignas(16) char epbr_rep_buf[sizeof(wifi_hal_rrm_report_t) + EPBR_PAD];
unsigned char epbr_sta_mac[6 + EPBR_PAD];
alignas(16) char epbr_app_buf[2048];
alignas(16) char epbr_appctrl_buf[512];
int epbr_publish_ret, epbr_publish_calls;
unsigned int epbr_last_data_len;
size_t epbr_len;   /* the len the runner passes */

em_epbr_test_case_t em_process_beacon_rep_suite[] = {
    /* name           data_len      publish_ret want_rc want_publish */
    { "ok_50",         50,          0,          0,      1 },
    { "short_frame",   0,           0,         -1,      0 },   /* len == min_len */
    { "data_too_big",  MAX_FRAME_SZ+1, 0,      -1,      0 },
    { "publish_fail",  50,          -7,        -7,      1 },
    { NULL, 0, 0, 0, 0 }  /* sentinel */
};

void construct_em_process_beacon_rep_input(const em_epbr_test_case_t *tc)
{
    size_t min_len = IEEE80211_HDRLEN + 1 + sizeof(((struct ieee80211_mgmt *)0)->u.action.u.rrm);

    memset(epbr_mgmt_buf, 0, sizeof(epbr_mgmt_buf));
    memset(epbr_rep_buf, 0, sizeof(epbr_rep_buf));
    memset(epbr_sta_mac, 0, sizeof(epbr_sta_mac));
    memset(epbr_app_buf, 0, sizeof(epbr_app_buf));
    memset(epbr_appctrl_buf, 0, sizeof(epbr_appctrl_buf));

    unsigned char mac[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    memcpy(epbr_sta_mac, mac, 6);

    wifi_hal_rrm_report_t *rep = (wifi_hal_rrm_report_t *)epbr_rep_buf;
    rep->dialog_token = 5;
    rep->size = 3;

    /* app->ctrl -> ctrl buffer (so &app->ctrl->handle is valid) */
    wifi_app_t *app = (wifi_app_t *)epbr_app_buf;
    app->ctrl = (decltype(app->ctrl))epbr_appctrl_buf;

    /* choose len: short_frame -> exactly min_len; else min_len + data_len
     * (data_too_big only needs len large; no actual payload is read). */
    if (tc->data_len == 0)            epbr_len = min_len;                 /* short_frame */
    else                              epbr_len = min_len + (size_t)tc->data_len;

    /* fill the frame payload region for the ok cases (the data_too_big case is
     * rejected before memcpy, so no real payload is needed) */
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)epbr_mgmt_buf;
    if (tc->data_len > 0 && (unsigned)tc->data_len <= MAX_FRAME_SZ)
        memset(mgmt->u.action.u.rrm.variable, 0xAB, tc->data_len);

    epbr_publish_ret = tc->publish_ret;
    epbr_publish_calls = 0;
    epbr_last_data_len = 0;
}

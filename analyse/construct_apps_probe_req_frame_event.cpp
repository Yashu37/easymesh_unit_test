/*
 * TEST CASES / CONSTRUCTOR: construct_apps_probe_req_frame_event
 * The caller-owned buffers are lpr_app_buf (struct wifi_app) and lpr_msg_buf
 * (frame_data_t); the runner poisons the LPR_PAD tail of both. The frame's
 * source MAC is AA:BB:CC:DD:EE:01 (key "aa:bb:cc:dd:ee:01" after to_mac_str).
 * Cases: new_entry, existing_same_ap (replace frame), existing_other_ap
 * (append), map_null, map_full (count > MAX_PROBE_ENTRIES).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char lpr_app_buf[sizeof(struct wifi_app) + LPR_PAD];
alignas(16) char lpr_msg_buf[sizeof(frame_data_t) + LPR_PAD];
int lpr_count_override;

lv_lpr_test_case_t apps_probe_req_frame_event_suite[] = {
    /* name              null cnt_ovr pre pre_ap msg_ap frames first upd key */
    { "new_entry",        0,   0,     0,  0,     1,     1,     1,   1, "aa:bb:cc:dd:ee:01" },
    { "existing_same_ap", 0,   0,     1,  1,     1,     1,     1,   1, "aa:bb:cc:dd:ee:01" },
    { "existing_other_ap",0,   0,     1,  2,     1,     2,     2,   1, "aa:bb:cc:dd:ee:01" },
    { "map_null",         1,   0,     0,  0,     1,     0,    -1,   0, "" },
    { "map_full",         0,   2001,  0,  0,     1,     0,    -1,   0, "" },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL }  /* sentinel */
};

void construct_apps_probe_req_frame_event_input(const lv_lpr_test_case_t *tc)
{
    memset(lpr_app_buf, 0, sizeof(lpr_app_buf));
    memset(lpr_msg_buf, 0, sizeof(lpr_msg_buf));
    struct wifi_app *app = (struct wifi_app *)lpr_app_buf;
    pthread_mutex_init(&app->data.u.levl.lock, NULL);
    app->data.u.levl.probe_req_map = tc->map_null ? NULL : (void *)lpr_app_buf;   /* any non-NULL token */

    frame_data_t *msg = (frame_data_t *)lpr_msg_buf;
    msg->frame.ap_index = tc->msg_ap;
    msg->frame.len = (unsigned int)sizeof(struct ieee80211_mgmt);
    struct ieee80211_mgmt *f = (struct ieee80211_mgmt *)msg->data;
    unsigned char sa[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    memcpy(f->sa, sa, 6);

    lpr_count_override = tc->count_override;
    lpr_setup("aa:bb:cc:dd:ee:01", tc->preexist, tc->pre_ap);
}

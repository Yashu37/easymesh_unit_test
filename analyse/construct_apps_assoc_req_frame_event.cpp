/*
 * TEST CASES / CONSTRUCTOR: construct_apps_assoc_req_frame_event
 * Caller-owned buffers: aar_app_buf (struct wifi_app) and aar_msg_buf
 * (frame_data_t); the runner poisons the AAR_PAD tail of both. The assoc
 * frame's source MAC is AA:BB:CC:DD:EE:01 (map key "aa:bb:cc:dd:ee:01").
 * n_frames < 0 = no map entry; otherwise the entry holds saved probe frames on
 * aps[].
 * Cases: no_probe (assoc only), probe_same_ap (probe on the assoc ap sent
 * first), probe_other_ap (any saved probe is sent), empty_entry (entry without
 * frames -> assoc only).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

alignas(16) char aar_app_buf[sizeof(struct wifi_app) + AAR_PAD];
alignas(16) char aar_msg_buf[sizeof(frame_data_t) + AAR_PAD];
char aar_sent_ns[AAR_MAX_SENDS][64];
int  aar_send_calls;

lv_aar_test_case_t apps_assoc_req_frame_event_suite[] = {
    /* name             n   aps    msg_ap sends ns0                                      ns1                                       remaining */
    { "no_probe",      -1, {0,0},    1,    1, "Device.WiFi.Events.VAP.2.Frames.Mgmt",  "",                                        0 },
    { "probe_same_ap",  2, {1,2},    1,    2, "Device.WiFi.Events.VAP.2.Frames.Mgmt",  "Device.WiFi.Events.VAP.2.Frames.Mgmt",    1 },
    { "probe_other_ap", 1, {3,0},    1,    2, "Device.WiFi.Events.VAP.4.Frames.Mgmt",  "Device.WiFi.Events.VAP.2.Frames.Mgmt",    0 },
    { "empty_entry",    0, {0,0},    1,    1, "Device.WiFi.Events.VAP.2.Frames.Mgmt",  "",                                        0 },
    { NULL, 0, {0,0}, 0, 0, NULL, NULL, 0 }  /* sentinel */
};

void construct_apps_assoc_req_frame_event_input(const lv_aar_test_case_t *tc)
{
    memset(aar_app_buf, 0, sizeof(aar_app_buf));
    memset(aar_msg_buf, 0, sizeof(aar_msg_buf));
    memset(aar_sent_ns, 0, sizeof(aar_sent_ns));
    aar_send_calls = 0;

    struct wifi_app *app = (struct wifi_app *)aar_app_buf;
    pthread_mutex_init(&app->data.u.levl.lock, NULL);
    app->data.u.levl.probe_req_map = (void *)aar_app_buf;   /* any non-NULL token */

    frame_data_t *msg = (frame_data_t *)aar_msg_buf;
    msg->frame.ap_index = tc->msg_ap;
    msg->frame.len = (unsigned int)sizeof(struct ieee80211_mgmt);
    struct ieee80211_mgmt *f = (struct ieee80211_mgmt *)msg->data;
    unsigned char sa[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    memcpy(f->sa, sa, 6);

    aar_setup("aa:bb:cc:dd:ee:01", tc->n_frames, tc->aps);
}

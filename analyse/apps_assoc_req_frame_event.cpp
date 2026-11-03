/*
 * HANDLER: apps_assoc_req_frame_event
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes; the
 * non-CONFIG_IEEE80211BE variant, as compiled for this tree, together with its
 * helper get_probe_req_in_band). Local arrays:
 *   - mac_addr_str_t mac_str : to_mac_str (17 chars + NUL), lower-cased in place;
 *   - char namespace[50]     : snprintf-bounded (<= 46 bytes + NUL).
 * Both bounded -> SAFE.
 *
 * Scaffolding (NOT under test): real OneWifi ds_dlist headers (ds_inc/);
 * hash_map_get is #define-redirected to a one-slot model; to_mac_str /
 * str_tolower local; mgmt_frame_bus_send records each namespace sent.
 * aar_setup / aar_result / aar_teardown are harness helpers that own the
 * ds_dlist-typed state.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include "common.h"
#include "ds_inc/ds_dlist.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE   "Device.WiFi.Events.VAP.%d.Frames.Mgmt"
/* 'namespace' is a C++ keyword (source is C): rename the identifier only */
#define namespace ns_buf

typedef struct {
    frame_data_t probe_frame;
    struct ds_dlist_node node;
} probe_frame_t;

typedef struct {
    unsigned int curr_time_alive;
    long curr_alive_time_sec;
    ds_dlist_t probe_req_frames_list;
    mac_addr_str_t mac_str;
} probe_req_elem_t;

/* --- one-slot hash map model + stubs --- */
static char aar_map_key[32];
static probe_req_elem_t *aar_map_elem;

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static void str_tolower(char *s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }
static void *aar_get(void *m, const char *key) { (void)m; return (aar_map_elem && strcmp(key, aar_map_key) == 0) ? aar_map_elem : NULL; }
#define hash_map_get(m, k)   aar_get((m), (k))
static void mgmt_frame_bus_send(void *handle, const char *ns, frame_data_t *msg)
{
    (void)handle; (void)msg;
    if (aar_send_calls < AAR_MAX_SENDS) snprintf(aar_sent_ns[aar_send_calls], sizeof(aar_sent_ns[0]), "%s", ns);
    aar_send_calls++;
}

/* ================= VERBATIM from wifi_levl.c ================= */
static void get_probe_req_in_band(wifi_app_t *app, probe_req_elem_t *elem, frame_data_t *msg,
    ds_dlist_t *probe_req_frames_to_send)
{
    probe_frame_t *probe_req_frame = NULL;
    probe_frame_t *tmp_probe_req_frame = NULL;
    ds_dlist_foreach_safe(&elem->probe_req_frames_list, probe_req_frame, tmp_probe_req_frame) {
        if (probe_req_frame->probe_frame.frame.ap_index == msg->frame.ap_index) {
            ds_dlist_remove(&elem->probe_req_frames_list, probe_req_frame);
            ds_dlist_insert_tail(probe_req_frames_to_send, probe_req_frame);
            return;
        }
    }

    if (ds_dlist_is_empty(&elem->probe_req_frames_list) == false) {
        // At this point just include any frame
        probe_req_frame = (probe_frame_t *)ds_dlist_head(&elem->probe_req_frames_list);
        ds_dlist_remove(&elem->probe_req_frames_list, probe_req_frame);
        ds_dlist_insert_tail(probe_req_frames_to_send, probe_req_frame);
    }
}

void apps_assoc_req_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str = { 0 };
    char *str;
    char namespace[50];
    probe_frame_t *probe_req_frame = NULL;
    probe_frame_t *tmp_probe_req_frame = NULL;

    ds_dlist_t probe_req_frames_to_send;
    ds_dlist_init(&probe_req_frames_to_send, probe_frame_t, node);

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str(frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }

    str_tolower(mac_str);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm);

    pthread_mutex_lock(&app->data.u.levl.lock);
    probe_req_elem_t *elem;
    elem = (probe_req_elem_t *)hash_map_get(app->data.u.levl.probe_req_map, mac_str);
    if (elem != NULL) {
        get_probe_req_in_band(app, elem, msg, &probe_req_frames_to_send);
    }
    pthread_mutex_unlock(&app->data.u.levl.lock);

    if (ds_dlist_is_empty(&probe_req_frames_to_send)) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d:probe not found for mac address:%s\n", __func__, __LINE__, str);
        //assert(1);
        // assoc request bus send
        snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
        mgmt_frame_bus_send(&app->handle, namespace, msg);
    } else {
        // probe request bus send
        ds_dlist_foreach_safe(&probe_req_frames_to_send, probe_req_frame, tmp_probe_req_frame) {
            snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE,
                probe_req_frame->probe_frame.frame.ap_index + 1);
            mgmt_frame_bus_send(&app->handle, namespace, &probe_req_frame->probe_frame);
            ds_dlist_remove(&probe_req_frames_to_send, probe_req_frame);
            free(probe_req_frame);
        }

        // assoc request bus send
        snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
        mgmt_frame_bus_send(&app->handle, namespace, msg);

        wifi_util_dbg_print(WIFI_APPS,
            "%s:%d Send probe and assoc ap_index:%d length:%d type:%d dir:%d rssi:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type,
            msg->frame.dir, msg->frame.sig_dbm);
    }
}

/* ================= harness helpers (own the ds_dlist-typed state) ================= */
static void aar_free_all(void)
{
    if (aar_map_elem) {
        probe_frame_t *f;
        while (ds_dlist_is_empty(&aar_map_elem->probe_req_frames_list) == false) {
            f = (probe_frame_t *)ds_dlist_head(&aar_map_elem->probe_req_frames_list);
            ds_dlist_remove(&aar_map_elem->probe_req_frames_list, f);
            free(f);
        }
        free(aar_map_elem);
        aar_map_elem = NULL;
    }
    aar_map_key[0] = 0;
}
/* Creates a map entry for key holding n_frames saved probe frames on ap list aps[] (n_frames < 0: no entry). */
void aar_setup(const char *key, int n_frames, const int *aps)
{
    aar_free_all();
    if (n_frames < 0) return;
    probe_req_elem_t *e = (probe_req_elem_t *)calloc(1, sizeof(probe_req_elem_t));
    snprintf(e->mac_str, sizeof(e->mac_str), "%s", key);
    ds_dlist_init(&e->probe_req_frames_list, probe_frame_t, node);
    for (int i = 0; i < n_frames; i++) {
        probe_frame_t *f = (probe_frame_t *)calloc(1, sizeof(probe_frame_t));
        f->probe_frame.frame.ap_index = aps[i];
        ds_dlist_insert_tail(&e->probe_req_frames_list, f);
    }
    snprintf(aar_map_key, sizeof(aar_map_key), "%s", key);
    aar_map_elem = e;
}
/* number of probe frames still saved in the map entry */
int aar_remaining(void)
{
    int n = 0;
    if (aar_map_elem) {
        probe_frame_t *p;
        ds_dlist_foreach(&aar_map_elem->probe_req_frames_list, p) { n++; }
    }
    return n;
}
void aar_teardown(void) { aar_free_all(); }

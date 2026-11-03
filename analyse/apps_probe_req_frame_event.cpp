/*
 * HANDLER: apps_probe_req_frame_event
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array:
 *   - mac_addr_str_t mac_str : filled by to_mac_str (17 chars + NUL), lower-cased
 *     in place by str_tolower and copied to elem->mac_str with
 *     memcpy(..., sizeof(mac_addr_str_t)). Bounded -> SAFE.
 * The handler also reads sizeof(frame_data_t) from the caller's msg and
 * the 6-byte frame->sa from msg->data.
 *
 * Scaffolding (NOT under test): the real OneWifi ds_dlist headers (copied in
 * ds_inc/); hash_map_count/get/put are #define-redirected to a one-slot model;
 * update_probe_map / str_tolower / get_current_time_in_sec / to_mac_str are
 * local. lpr_setup / lpr_result are harness helpers used by the constructor
 * and runner (they own the types that need ds_dlist).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include "common.h"
#include "ds_inc/ds_dlist.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_util_info_print(m, ...) do {} while (0)
#define MAX_PROBE_ENTRIES 2000

typedef struct {
    frame_data_t probe_frame;
    struct ds_dlist_node node;
} probe_frame_t;

typedef struct {
    unsigned int curr_time_alive;
    time_t curr_alive_time_sec;
    ds_dlist_t probe_req_frames_list;
    mac_addr_str_t mac_str;
} probe_req_elem_t;

/* --- one-slot hash map model + stubs --- */
static char lpr_map_key[32];
static probe_req_elem_t *lpr_map_elem;
static int lpr_update_calls;

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static void str_tolower(char *s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }
static long get_current_time_in_sec(void) { return 12345; }
static int lpr_count(void *m) { (void)m; return lpr_count_override ? lpr_count_override : (lpr_map_elem ? 1 : 0); }
static void *lpr_get(void *m, const char *key) { (void)m; return (lpr_map_elem && strcmp(key, lpr_map_key) == 0) ? lpr_map_elem : NULL; }
static int lpr_put(void *m, char *key, void *data)
{
    (void)m;
    snprintf(lpr_map_key, sizeof(lpr_map_key), "%s", key);
    free(key);                      /* handler passes strdup(mac_str) */
    lpr_map_elem = (probe_req_elem_t *)data;
    return 0;
}
static void update_probe_map(wifi_app_t *a, char *k) { (void)a; (void)k; lpr_update_calls++; }
#define hash_map_count(m)       lpr_count(m)
#define hash_map_get(m, k)      lpr_get((m), (k))
#define hash_map_put(m, k, d)   lpr_put((m), (k), (d))

/* ================= VERBATIM from wifi_levl.c ================= */
void apps_probe_req_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str = { 0 };
    char *str;
    probe_req_elem_t *elem;

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str((unsigned char *)frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }
    pthread_mutex_lock(&app->data.u.levl.lock);
    if (app->data.u.levl.probe_req_map == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d probe hash map is null\r\n", __func__, __LINE__);
        pthread_mutex_unlock(&app->data.u.levl.lock);
        return;
    }
    if (hash_map_count(app->data.u.levl.probe_req_map) > MAX_PROBE_ENTRIES) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d [SKIP] wifi mgmt frame message: ap_index:%d length:%d src mac:%s rssi:%d\r\n", __func__,
                            __LINE__, msg->frame.ap_index, msg->frame.len, str, msg->frame.sig_dbm);
        pthread_mutex_unlock(&app->data.u.levl.lock);
        return;
    }

    update_probe_map(app, str);

    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm);

    str_tolower(mac_str);
    probe_frame_t *msg_copy = (probe_frame_t *)malloc(sizeof(probe_frame_t));
    if (msg_copy == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d malloc failed for probe_frame_t\r\n", __func__,
            __LINE__);
        pthread_mutex_unlock(&app->data.u.levl.lock);
        return;
    }
    memset(msg_copy, 0, sizeof(probe_frame_t));
    memcpy(&msg_copy->probe_frame, msg, sizeof(frame_data_t));

    if ((elem = (probe_req_elem_t *)hash_map_get(app->data.u.levl.probe_req_map, mac_str)) == NULL) {
        elem = (probe_req_elem_t *)malloc(sizeof(probe_req_elem_t));
        if (elem == NULL) {
            wifi_util_error_print(WIFI_APPS, "%s:%d malloc failed for probe_req_elem_t\r\n",
                __func__, __LINE__);
            pthread_mutex_unlock(&app->data.u.levl.lock);
            free(msg_copy);
            return;
        }
        memset(elem, 0, sizeof(probe_req_elem_t));
        memcpy(elem->mac_str, mac_str, sizeof(mac_addr_str_t));

        ds_dlist_init(&elem->probe_req_frames_list, probe_frame_t, node);
        ds_dlist_insert_tail(&elem->probe_req_frames_list, msg_copy);
        hash_map_put(app->data.u.levl.probe_req_map, strdup(mac_str), elem);
        elem->curr_alive_time_sec = get_current_time_in_sec();
        wifi_util_info_print(WIFI_APPS,"%s:%d wifi mgmt probe frame message for %s time:%ld\r\n", __func__, __LINE__, mac_str, elem->curr_alive_time_sec);
    } else {
        bool found = false;
        probe_frame_t *saved_probe_req = NULL;

        ds_dlist_foreach(&elem->probe_req_frames_list, saved_probe_req) {
            if (saved_probe_req->probe_frame.frame.ap_index == msg->frame.ap_index) {
                memset(&saved_probe_req->probe_frame, 0, sizeof(frame_data_t));
                memcpy(&saved_probe_req->probe_frame, msg, sizeof(frame_data_t));
                found = true;
                free(msg_copy);
                break;
            }
        }

        if (!found) {
            ds_dlist_insert_tail(&elem->probe_req_frames_list, msg_copy);
        }
    }
    pthread_mutex_unlock(&app->data.u.levl.lock);
}

/* ================= harness helpers (own the ds_dlist-typed state) ================= */
static void lpr_free_all(void)
{
    if (lpr_map_elem) {
        probe_frame_t *f;
        while (ds_dlist_is_empty(&lpr_map_elem->probe_req_frames_list) == false) {
            f = (probe_frame_t *)ds_dlist_head(&lpr_map_elem->probe_req_frames_list);
            ds_dlist_remove(&lpr_map_elem->probe_req_frames_list, f);
            free(f);
        }
        free(lpr_map_elem);
        lpr_map_elem = NULL;
    }
    lpr_map_key[0] = 0;
}
/* preexist: 1 = map already holds an entry for key with one saved frame on pre_ap */
void lpr_setup(const char *key, int preexist, int pre_ap)
{
    lpr_free_all();
    lpr_update_calls = 0;
    if (!preexist) return;
    probe_req_elem_t *e = (probe_req_elem_t *)calloc(1, sizeof(probe_req_elem_t));
    snprintf(e->mac_str, sizeof(e->mac_str), "%s", key);
    ds_dlist_init(&e->probe_req_frames_list, probe_frame_t, node);
    probe_frame_t *f = (probe_frame_t *)calloc(1, sizeof(probe_frame_t));
    f->probe_frame.frame.ap_index = pre_ap;
    ds_dlist_insert_tail(&e->probe_req_frames_list, f);
    snprintf(lpr_map_key, sizeof(lpr_map_key), "%s", key);
    lpr_map_elem = e;
}
/* returns number of saved frames; also reports the map key and update_probe_map calls */
int lpr_result(char *key_out, size_t key_sz, int *update_calls, int *first_ap)
{
    int n = 0;
    *first_ap = -1;
    snprintf(key_out, key_sz, "%s", lpr_map_key);
    *update_calls = lpr_update_calls;
    if (lpr_map_elem) {
        probe_frame_t *p;
        ds_dlist_foreach(&lpr_map_elem->probe_req_frames_list, p) {
            if (n == 0) *first_ap = p->probe_frame.frame.ap_index;
            n++;
        }
    }
    return n;
}
void lpr_teardown(void) { lpr_free_all(); }

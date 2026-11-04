/*
 * HANDLER: process_csi_stop_levl_locked
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (only "static"
 * dropped). Local array:
 *   - mac_addr_str_t mac_str : memset + to_mac_str (17 chars + NUL) -> bounded,
 *     SAFE.
 * The handler walks the current-sounding map, stops each entry, advances the
 * iterator BEFORE removing the current entry, then moves the entry to the
 * pending map under a strdup'd key (ASan checks for use after free on the
 * iterator / entries and for the key allocation).
 *
 * Scaffolding (NOT under test): get_wifictrl_obj returns lcs_ctrl_buf (or
 * NULL); the two hash maps are small array models (current map = array with
 * stable positions, pending map = recording list); csi_stop_fn,
 * levl_csi_status_publish and the scheduler calls are recording stubs;
 * to_mac_str is local.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_app_inst_levl 5

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_ctrl_t *get_wifictrl_obj(void) { return lcs_null_ctrl ? NULL : (wifi_ctrl_t *)lcs_ctrl_buf; }
static void scheduler_cancel_timer_task(void *s, int id) { (void)s; lcs_cancel_calls++; lcs_cancel_id = id; }
static void scheduler_free_timer_task_arg(void *s, int id) { (void)s; (void)id; lcs_freearg_calls++; }
static int levl_csi_status_publish(void *handle, unsigned char *mac, unsigned int status)
{
    (void)handle; (void)mac; lcs_pub_calls++; lcs_pub_status = (int)status; return 0;
}

/* current-sounding map model: array with stable positions (removal leaves a hole) */
static void *lcs_get_first(void *m)
{
    (void)m;
    for (int i = 0; i < lcs_n; i++) if (lcs_curr[i]) return lcs_curr[i];
    return NULL;
}
static void *lcs_get_next(void *m, void *cur)
{
    (void)m;
    int i = 0;
    while (i < lcs_n && lcs_curr[i] != cur) i++;
    for (i++; i < lcs_n; i++) if (lcs_curr[i]) return lcs_curr[i];
    return NULL;
}
static void *lcs_remove(void *m, const char *key)
{
    (void)m;
    for (int i = 0; i < lcs_n; i++) {
        if (lcs_curr[i]) {
            mac_addr_str_t k;
            to_mac_str(lcs_curr[i]->mac_addr, k);
            if (strcmp(k, key) == 0) { levl_sched_data_t *e = lcs_curr[i]; lcs_curr[i] = NULL; return e; }
        }
    }
    return NULL;
}
static int lcs_put(void *m, char *key, void *val)
{
    (void)m;
    if (lcs_pend_n < 4) { lcs_pend_keys[lcs_pend_n] = key; lcs_pend_vals[lcs_pend_n] = (levl_sched_data_t *)val; lcs_pend_n++; }
    return 0;
}
#define hash_map_get_first(m)      lcs_get_first(m)
#define hash_map_get_next(m, c)    lcs_get_next((m), (c))
#define hash_map_remove(m, k)      lcs_remove((m), (k))
#define hash_map_put(m, k, v)      lcs_put((m), (k), (v))

/* ================= VERBATIM from wifi_levl.c (static dropped) ================= */
int process_csi_stop_levl_locked(wifi_app_t *app)
{
    mac_addr_str_t mac_str = { 0 };
    levl_sched_data_t *tmp_data = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    levl_sched_data_t *levl_sched_data = NULL;
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    wifi_app_t *csi_app = app->data.u.levl.csi_app;

    if (app->data.u.levl.curr_sounding_mac_map == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    levl_sched_data = (levl_sched_data_t *)hash_map_get_first(app->data.u.levl.curr_sounding_mac_map);
    while(levl_sched_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str((unsigned char *)levl_sched_data->mac_addr, mac_str);
        if (levl_sched_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, levl_sched_data->sched_handler_id);
            scheduler_free_timer_task_arg(ctrl->sched, levl_sched_data->sched_handler_id);
            levl_sched_data->sched_handler_id = 0;
        }
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, levl_sched_data->ap_index, levl_sched_data->mac_addr, wifi_app_inst_levl);
        levl_csi_status_publish(&app->handle, levl_sched_data->mac_addr, 0);
        levl_sched_data = hash_map_get_next(app->data.u.levl.curr_sounding_mac_map, levl_sched_data);
        tmp_data = (levl_sched_data_t *)hash_map_remove(app->data.u.levl.curr_sounding_mac_map, mac_str);
        hash_map_put(app->data.u.levl.pending_mac_map, strdup(mac_str), tmp_data);
    }
    return 0;
}

/* ================= harness helpers ================= */
levl_sched_data_t *lcs_curr[4];
int lcs_n;
char *lcs_pend_keys[4];
levl_sched_data_t *lcs_pend_vals[4];
int lcs_pend_n;
void lcs_set_entries(int n, int sched_id)
{
    for (int i = 0; i < lcs_n; i++) if (lcs_curr[i]) { free(lcs_curr[i]); lcs_curr[i] = NULL; }
    for (int i = 0; i < lcs_pend_n; i++) { free(lcs_pend_keys[i]); free(lcs_pend_vals[i]); }
    lcs_pend_n = 0; lcs_n = n;
    for (int i = 0; i < n; i++) {
        lcs_curr[i] = (levl_sched_data_t *)calloc(1, sizeof(levl_sched_data_t));
        unsigned char m[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,(unsigned char)(i + 1)};
        memcpy(lcs_curr[i]->mac_addr, m, 6);
        lcs_curr[i]->ap_index = 3 + i;
        lcs_curr[i]->sched_handler_id = sched_id;
    }
}
int lcs_curr_count(void) { int c = 0; for (int i = 0; i < lcs_n; i++) if (lcs_curr[i]) c++; return c; }
int lcs_pend_count(void) { return lcs_pend_n; }
int lcs_pend_ok(void)    /* pending keys are the MAC strings of the moved entries, in order */
{
    for (int i = 0; i < lcs_pend_n; i++) {
        mac_addr_str_t k;
        to_mac_str(lcs_pend_vals[i]->mac_addr, k);
        if (!lcs_pend_keys[i] || strcmp(lcs_pend_keys[i], k) != 0 || lcs_pend_vals[i]->sched_handler_id != 0) return 0;
    }
    return 1;
}

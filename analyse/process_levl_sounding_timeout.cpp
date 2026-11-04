/*
 * HANDLER: process_levl_sounding_timeout
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t mac_str : to_mac_str (17 chars + NUL);
 *   - mac_address_t stop_mac : 6-byte memcpy from the sounding entry.
 * Both bounded -> SAFE. The handler frees t_data on every return path (and the
 * removed sounding entry), which ASan checks for double-free / use-after-free.
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_app_by_inst return the
 * lst_* buffers (or NULL per case); the current-sounding hash map is a
 * one-slot model; csi_stop_fn, levl_csi_status_publish and
 * schedule_from_pending_map are recording stubs; to_mac_str is local.
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
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_app_inst_levl 5

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_ctrl_t *get_wifictrl_obj(void) { return lst_null_ctrl ? NULL : (wifi_ctrl_t *)lst_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lst_null_app ? NULL : (wifi_app_t *)lst_app_buf; }
static levl_sched_data_t *lst_slot;      /* entry in the current-sounding map (heap) */
static char lst_slot_key[32];
static void *lst_get(void *m, const char *key) { (void)m; return (lst_slot && strcmp(key, lst_slot_key) == 0) ? lst_slot : NULL; }
static void *lst_remove(void *m, const char *key)
{
    (void)m;
    if (lst_slot && strcmp(key, lst_slot_key) == 0) { levl_sched_data_t *e = lst_slot; lst_slot = NULL; return e; }
    return NULL;
}
static int levl_csi_status_publish(void *handle, unsigned char *mac, unsigned int status)
{
    (void)handle; lst_pub_calls++; lst_pub_status = (int)status; memcpy(lst_pub_mac, mac, 6); return 0;
}
static int schedule_from_pending_map(wifi_app_t *a) { (void)a; lst_sched_calls++; return 0; }
#define hash_map_get(m, k)      lst_get((m), (k))
#define hash_map_remove(m, k)   lst_remove((m), (k))

/* ================= VERBATIM from wifi_levl.c (static dropped) ================= */
int process_levl_sounding_timeout(timeout_data_t *t_data)
{
    hash_map_t  *curr_map = NULL;
    mac_addr_str_t mac_str = { 0 };
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    levl_sched_data_t *levl_sc_data = NULL;
    levl_sched_data_t *removed_data = NULL;
    mac_address_t stop_mac = { 0 };
    int stop_ap_index = 0;
    wifi_app_t *wifi_app =  NULL;

    if (t_data == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    if (ctrl == NULL) {
        free(t_data);
        return -1;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        free(t_data);
        return -1;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        free(t_data);
        return -1;
    }

    wifi_app_t *csi_app = wifi_app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        free(t_data);
        return -1;
    }
    pthread_mutex_lock(&wifi_app->data.u.levl.lock);
    to_mac_str((unsigned char *)(t_data->mac_addr), mac_str);
    curr_map = wifi_app->data.u.levl.curr_sounding_mac_map;
    if (curr_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL hash map\n", __func__, __LINE__);
        pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
        free(t_data);
        return -1;
    }

    wifi_util_dbg_print(WIFI_APPS,
        "%s:%d timeout ap:%d mac:%02x..%02x\n",
        __func__, __LINE__, t_data->ap_index, t_data->mac_addr[0], t_data->mac_addr[5]);

    levl_sc_data = (levl_sched_data_t *)hash_map_get(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        memcpy(stop_mac, levl_sc_data->mac_addr, sizeof(mac_address_t));
        stop_ap_index = levl_sc_data->ap_index;
        removed_data = (levl_sched_data_t *)hash_map_remove(curr_map, mac_str);
    }
    if (removed_data != NULL) {
        wifi_util_dbg_print(WIFI_APPS,
            "timeout detached mac:%02x..%02x\n",
            stop_mac[0], stop_mac[5]);
        wifi_util_error_print(WIFI_APPS,"%s:%d Disable CSI Sounding for %02x:...%02x\n", __func__, __LINE__, stop_mac[0], stop_mac[5]);
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, stop_ap_index, stop_mac, wifi_app_inst_levl);
    }
    pthread_mutex_unlock(&wifi_app->data.u.levl.lock);

    if (removed_data != NULL) {
        levl_csi_status_publish(&wifi_app->handle, stop_mac, 0);
        free(removed_data);
    }
    schedule_from_pending_map(wifi_app);
    free(t_data);
    return 0;
}

/* ================= harness helpers ================= */
void lst_set_slot(const unsigned char *mac, int ap_index)
{
    if (lst_slot) { free(lst_slot); lst_slot = NULL; }
    if (!mac) return;
    lst_slot = (levl_sched_data_t *)calloc(1, sizeof(levl_sched_data_t));
    memcpy(lst_slot->mac_addr, mac, 6);
    lst_slot->ap_index = (unsigned int)ap_index;
    mac_addr_str_t k;
    to_mac_str(lst_slot->mac_addr, k);
    snprintf(lst_slot_key, sizeof(lst_slot_key), "%s", k);
}
int lst_slot_present(void) { return lst_slot != NULL; }

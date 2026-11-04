/*
 * HANDLER: levl_disassoc_device_event
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (no changes).
 * Local array:
 *   - mac_addr_str_t mac_str : to_mac_str (17 chars + NUL) -> bounded, SAFE.
 * The handler frees the removed sounding / pending entries (ASan checks for
 * double free / use after free).
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_app_by_inst return the
 * lds_* buffers (or NULL per case); the current-sounding and pending maps are
 * one-slot models (told apart by the map token); csi_stop_fn,
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
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_app_inst_levl 5

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)lds_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lds_null_app ? NULL : (wifi_app_t *)lds_app_buf; }
static levl_sched_data_t *lds_curr_slot, *lds_pend_slot;
static char lds_curr_key[32], lds_pend_key[32];
static void *lds_remove(void *m, const char *key)
{
    levl_sched_data_t **s = (m == (void *)lds_csi_buf) ? &lds_pend_slot : &lds_curr_slot;
    const char *k = (m == (void *)lds_csi_buf) ? lds_pend_key : lds_curr_key;
    if (*s && strcmp(key, k) == 0) { levl_sched_data_t *e = *s; *s = NULL; return e; }
    return NULL;
}
static void scheduler_cancel_timer_task(void *s, int id) { (void)s; lds_cancel_calls++; lds_cancel_id = id; }
static void scheduler_free_timer_task_arg(void *s, int id) { (void)s; (void)id; lds_freearg_calls++; }
static int levl_csi_status_publish(void *handle, unsigned char *mac, unsigned int status)
{
    (void)handle; lds_pub_calls++; lds_pub_status = (int)status; memcpy(lds_pub_mac, mac, 6); return 0;
}
#define hash_map_remove(m, k)   lds_remove((m), (k))

/* ================= VERBATIM from wifi_levl.c ================= */
void levl_disassoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    levl_sched_data_t *levl_sc_data = NULL;
    levl_sched_data_t *p_sc_data = NULL;
    hash_map_t *p_map = NULL, *curr_map = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr = NULL;
    mac_addr_str_t mac_str;
    wifi_app_t *wifi_app =  NULL;
    apps_mgr = &ctrl->apps_mgr;

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }
    pthread_mutex_lock(&wifi_app->data.u.levl.lock);
    wifi_app_t *csi_app = wifi_app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
        return;
    }

    p_map = wifi_app->data.u.levl.pending_mac_map;
    curr_map = wifi_app->data.u.levl.curr_sounding_mac_map;
    if ((curr_map == NULL) || (p_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL hash map Unable to handle disassoc\n", __func__, __LINE__);
        pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
        return;
    }

    to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, mac_str);

    if (wifi_app->data.u.levl.num_current_sounding > 0) {
        --(wifi_app->data.u.levl.num_current_sounding);
    } else {
        wifi_app->data.u.levl.num_current_sounding = 0;
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_remove(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        //Cancel scheduler Task
        if (levl_sc_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, levl_sc_data->sched_handler_id);
            scheduler_free_timer_task_arg(ctrl->sched, levl_sc_data->sched_handler_id);
            levl_sc_data->sched_handler_id = 0;
        }
        //Disable CSI Sounding
        wifi_util_error_print(WIFI_APPS,"%s:%d Disabling Sounding for MAC %02x:...:%02x\n", __func__, __LINE__,
                assoc_data->dev_stats.cli_MACAddress[0],assoc_data->dev_stats.cli_MACAddress[5]);
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, assoc_data->ap_index, assoc_data->dev_stats.cli_MACAddress, wifi_app_inst_levl);
    }
    p_sc_data = (levl_sched_data_t *)hash_map_remove(p_map, mac_str);

    if (p_sc_data != NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Removing from Pending List\n", __func__, __LINE__);
        free(p_sc_data);
    }
    pthread_mutex_unlock(&wifi_app->data.u.levl.lock);

    if (levl_sc_data != NULL) {
        levl_csi_status_publish(&wifi_app->handle, assoc_data->dev_stats.cli_MACAddress, 0);
        free(levl_sc_data);
    }
    return;
}

/* ================= harness helpers ================= */
void lds_set_slots(const unsigned char *mac, int curr, int sched_id, int pend)
{
    if (lds_curr_slot) { free(lds_curr_slot); lds_curr_slot = NULL; }
    if (lds_pend_slot) { free(lds_pend_slot); lds_pend_slot = NULL; }
    if (!mac) return;
    mac_addr_str_t k;
    if (curr) {
        lds_curr_slot = (levl_sched_data_t *)calloc(1, sizeof(levl_sched_data_t));
        memcpy(lds_curr_slot->mac_addr, mac, 6);
        lds_curr_slot->sched_handler_id = sched_id;
        to_mac_str(lds_curr_slot->mac_addr, k);
        snprintf(lds_curr_key, sizeof(lds_curr_key), "%s", k);
    }
    if (pend) {
        lds_pend_slot = (levl_sched_data_t *)calloc(1, sizeof(levl_sched_data_t));
        memcpy(lds_pend_slot->mac_addr, mac, 6);
        to_mac_str(lds_pend_slot->mac_addr, k);
        snprintf(lds_pend_key, sizeof(lds_pend_key), "%s", k);
    }
}
int lds_curr_present(void) { return lds_curr_slot != NULL; }
int lds_pend_present(void) { return lds_pend_slot != NULL; }

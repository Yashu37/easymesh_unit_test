/*
 * HANDLER: schedule_mac_for_sounding_locked
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (only "static"
 * dropped). Local array:
 *   - mac_addr_str_t mac_str : filled by to_mac_str (17 chars + NUL); the
 *     6-byte mac_address argument is read with fixed 6-byte memcpys.
 * Bounded -> SAFE. The function allocates levl_sc_data / t_data and either
 * hands them to a map / the scheduler or frees them (ASan checks leaks/double
 * frees through the paths below).
 *
 * Scaffolding (NOT under test): get_wifictrl_obj / get_app_by_inst return the
 * lsm_* buffers; the two hash maps (current / pending) are modelled by token
 * pointers with call recorders; csi_start_fn / csi_stop_fn,
 * scheduler_add_timer_task and levl_csi_status_publish are recording stubs;
 * process_levl_postpone_sounding is a local no-op; process_levl_sounding_timeout
 * is the real function from its own TU.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)
#define wifi_util_info_print(m, ...) do {} while (0)
#define wifi_app_inst_levl 5
#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#ifndef FALSE
#define FALSE 0
#endif

int process_levl_sounding_timeout(timeout_data_t *t_data);          /* real fn, other TU */
static int process_levl_postpone_sounding(wifi_app_t *app) { (void)app; return 0; }

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)lsm_ctrl_buf; }
static wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *m, int inst) { (void)m; (void)inst; return lsm_null_app ? NULL : (wifi_app_t *)lsm_app_buf; }

static levl_sched_data_t lsm_dummy_existing;
static void lsm_own(void *p) { if (lsm_n_owned < 8) lsm_owned[lsm_n_owned++] = p; }
static void *lsm_get(void *m, const char *key)
{
    (void)key;
    return (m == (void *)&lsm_curr_token && lsm_dup) ? (void *)&lsm_dummy_existing : NULL;
}
static int lsm_count(void *m) { return (m == (void *)&lsm_curr_token) ? lsm_curr_count : 0; }
static int lsm_put(void *m, char *key, void *data)
{
    if (m == (void *)&lsm_curr_token) lsm_curr_put++; else lsm_pend_put++;
    snprintf(lsm_last_key, sizeof(lsm_last_key), "%s", key);
    free(key);                                   /* handler passes strdup(mac_str) */
    lsm_own(data);
    return 0;
}
static int lsm_sched(int *id, void *arg, int interval)
{
    (void)id; (void)interval;
    lsm_sched_calls++;
    if (lsm_sched_ret == 0 && arg == lsm_last_tdata_expect) lsm_own(arg);   /* scheduler owns it */
    return lsm_sched_ret;
}
static int levl_csi_status_publish(void *handle, unsigned char *mac, unsigned int status)
{
    (void)handle; (void)mac;
    if (lsm_pub_calls < 4) lsm_pub_status[lsm_pub_calls] = (int)status;
    lsm_pub_calls++;
    return 0;
}
#define hash_map_get(m, k)      lsm_get((m), (k))
#define hash_map_count(m)       lsm_count(m)
#define hash_map_put(m, k, d)   lsm_put((m), (k), (d))
/* scheduler_add_timer_task(sched, FALSE, &id, fn, arg, interval, count, FALSE): timeout task owns arg */
#define scheduler_add_timer_task(s, a, id, fn, arg, iv, c, b)  lsm_sched((id), (void *)(arg), (iv))

/* ================= VERBATIM from wifi_levl.c (static dropped) ================= */
int schedule_mac_for_sounding_locked(int ap_index, mac_address_t mac_address, int duration, int interval)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    hash_map_t *curr_map = NULL, *p_map = NULL;

    wifi_apps_mgr_t *apps_mgr;
    mac_addr_str_t mac_str;
    timeout_data_t *t_data = NULL;
    struct timeval t_now = {0};
    apps_mgr = &ctrl->apps_mgr;
    levl_sched_data_t *levl_sc_data = NULL;
    wifi_app_t *wifi_app = NULL;
    int curr_map_count = 0;

    to_mac_str((unsigned char *)mac_address, mac_str);
    wifi_util_dbg_print(WIFI_APPS,
        "%s:%d schedule ap:%d duration:%d interval:%d mac:%02x..%02x\n",
        __func__, __LINE__, ap_index, duration, interval, mac_address[0], mac_address[5]);
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL wifi_app pointer\n", __func__, __LINE__);
        return -1;
    }
    if (!wifi_app->data.u.levl.csi_event_subscribed) {
        wifi_util_info_print(WIFI_APPS,"%s:%d No SUBSCRIBERS not processing MAC for Sounding \n", __func__, __LINE__);
        return 0;
    }

    wifi_app_t *csi_app = wifi_app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL csi_app pointer\n", __func__, __LINE__);
        return -1;
    }

    p_map = wifi_app->data.u.levl.pending_mac_map;
    curr_map = wifi_app->data.u.levl.curr_sounding_mac_map;
    if ((curr_map == NULL) || (p_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL hash map\n", __func__, __LINE__);
        return -1;
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_get(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        wifi_util_info_print(WIFI_APPS,"%s:%d Multiple request for same MAC %02x...%02x\n", __func__, __LINE__, mac_address[0], mac_address[5]);
        return -1;
    }

    levl_sc_data = (levl_sched_data_t *)malloc(sizeof(levl_sched_data_t));
    if (levl_sc_data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL  Pointer\n", __func__, __LINE__);
        return -1;
    }
    memset(levl_sc_data, 0, sizeof(levl_sched_data_t));
    memcpy(levl_sc_data->mac_addr, mac_address, sizeof(mac_address_t));
    levl_sc_data->ap_index = ap_index;
    levl_sc_data->duration = duration;
    levl_sc_data->interval = interval;
    levl_sc_data->last_time_publish = t_now;

    if (wifi_app->data.u.levl.paused) {
        wifi_util_info_print(WIFI_APPS,"%s:%d Speed test in progress, pushing to control map\n", __func__, __LINE__);
        hash_map_put(p_map, strdup(mac_str), levl_sc_data);
        return 0;
    }

    curr_map_count = hash_map_count(curr_map);
    if ((curr_map_count < wifi_app->data.u.levl.max_num_csi_clients)) {
        t_data = (timeout_data_t *)malloc(sizeof(timeout_data_t));
        if (t_data == NULL) {
            free(levl_sc_data);
            wifi_util_error_print(WIFI_APPS,"%s:%d NULL wifi_app pointer\n", __func__, __LINE__);
            return -1;
        }
        memset(t_data, 0, sizeof(timeout_data_t));
        memcpy(t_data->mac_addr, mac_address, sizeof(mac_address_t));
        t_data->ap_index = ap_index;
        lsm_last_tdata_expect = t_data;
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Enabling CSI for MAC %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__,
                           mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
        levl_sc_data->ap_index = ap_index;
        if (csi_app->data.u.csi.csi_fns.csi_start_fn(csi_app, ap_index, mac_address, wifi_app_inst_levl) < 0) {
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Unable to schedule sounding for the client, pushing to pending list.\n", __func__, __LINE__);
            hash_map_put(p_map, strdup(mac_str), levl_sc_data);
            if ((hash_map_count(curr_map) == 0) && (wifi_app->data.u.levl.postpone_sched_handler_id == 0)) {
                scheduler_add_timer_task(ctrl->sched, FALSE, &(wifi_app->data.u.levl.postpone_sched_handler_id),
                   process_levl_postpone_sounding, wifi_app, 2000, 1, FALSE);
            }
            free(t_data);
            return RETURN_OK;
        }
        levl_csi_status_publish(&wifi_app->handle, mac_address, 1);

        if (scheduler_add_timer_task(ctrl->sched, FALSE, &(levl_sc_data->sched_handler_id),
            process_levl_sounding_timeout, t_data, levl_sc_data->duration, 1, FALSE) != 0) {
            csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, ap_index, mac_address, wifi_app_inst_levl);
            levl_csi_status_publish(&wifi_app->handle, mac_address, 0);
            free(t_data);
            free(levl_sc_data);
            return RETURN_ERR;
        }
        hash_map_put(curr_map, strdup(mac_str), levl_sc_data);
    } else {
        //Push MAC to pending queue
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Pushing to Pending list MAC %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__,
                           mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
        hash_map_put(p_map, strdup(mac_str), levl_sc_data);
    }
    return RETURN_OK;
}

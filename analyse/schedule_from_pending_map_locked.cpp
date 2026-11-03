/*
 * HANDLER: schedule_from_pending_map_locked
 *
 * Copied VERBATIM from OneWifi source/apps/levl/wifi_levl.c (only "static"
 * dropped). Local arrays:
 *   - mac_addr_str_t mac_str : filled by to_mac_str (17 chars + NUL);
 *   - mac_addr_t mac_addr    : 6-byte memcpy from the pending entry.
 * Both are bounded; the pending-map walk is driven by the hash map. SAFE.
 *
 * Scaffolding (NOT under test): the hash_map_* calls are #define-redirected to
 * a small model over lsp_entries[] (heap entries, freed by the handler as in
 * the original); get_ap_index_from_clientmac returns (signed char)mac[5];
 * schedule_mac_for_sounding_locked records its arguments; to_mac_str is local.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define WIFI_APPS 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif
#define wifi_util_error_print(m, ...) do {} while (0)

static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static int lsp_count(void *m) { (void)m; return lsp_n; }
static void *lsp_first(void *m) { (void)m; return lsp_n ? lsp_entries[0] : NULL; }
static void *lsp_next(void *m, void *cur)
{
    (void)m;
    for (int i = 0; i < lsp_n; i++)
        if (lsp_entries[i] == cur) return (i + 1 < lsp_n) ? lsp_entries[i + 1] : NULL;
    return NULL;
}
static void *lsp_remove(void *m, const char *key)
{
    (void)m;
    for (int i = 0; i < lsp_n; i++) {
        mac_addr_str_t k;
        to_mac_str(lsp_entries[i]->mac_addr, k);
        if (strcmp(k, key) == 0) {
            levl_sched_data_t *e = lsp_entries[i];
            for (int j = i; j + 1 < lsp_n; j++) lsp_entries[j] = lsp_entries[j + 1];
            lsp_n--;
            return e;
        }
    }
    return NULL;
}
static int get_ap_index_from_clientmac(unsigned char *mac) { return (int)(signed char)mac[5]; }
static int lsp_sched(int ap, unsigned char *mac, int dur, int intv)
{
    lsp_sched_calls++; lsp_sched_ap = ap; lsp_sched_dur = dur; lsp_sched_int = intv;
    memcpy(lsp_sched_mac, mac, 6);
    return 0;
}
#define hash_map_count(m)          lsp_count(m)
#define hash_map_get_first(m)      lsp_first(m)
#define hash_map_get_next(m, d)    lsp_next((m), (d))
#define hash_map_remove(m, k)      lsp_remove((m), (k))
#define schedule_mac_for_sounding_locked(a, m, d, i)  lsp_sched((a), (unsigned char *)(m), (d), (i))
#define get_ap_index_from_clientmac(m)  get_ap_index_from_clientmac((unsigned char *)(m))

/* ================= VERBATIM from wifi_levl.c (static dropped) ================= */
int schedule_from_pending_map_locked(wifi_app_t *wifi_app)
{
    int p_map_count = 0, ap_index = 0;
    int duration = 0, interval = 0;
    hash_map_t *p_map = NULL;
    mac_addr_str_t mac_str = { 0 };
    mac_addr_t mac_addr;

    levl_sched_data_t *levl_sc_data = NULL, *tmp_data = NULL;

    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    p_map = wifi_app->data.u.levl.pending_mac_map;
    if (p_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pending map\n", __func__, __LINE__);
        return -1;
    }

    p_map_count = hash_map_count(p_map);
    wifi_util_dbg_print(WIFI_APPS,
        "%s:%d pending:%d active:%d max:%d\n",
        __func__, __LINE__, p_map_count,
        wifi_app->data.u.levl.num_current_sounding,
        wifi_app->data.u.levl.max_num_csi_clients);
    if ((p_map_count > 0) && (wifi_app->data.u.levl.num_current_sounding < wifi_app->data.u.levl.max_num_csi_clients)) {
        levl_sc_data = (levl_sched_data_t *)hash_map_get_first(p_map);
        while(levl_sc_data != NULL)
        {
            ap_index = get_ap_index_from_clientmac(levl_sc_data->mac_addr);
            memset(mac_str, 0, sizeof(mac_addr_str_t));
            to_mac_str((unsigned char *)levl_sc_data->mac_addr, mac_str);
            if (ap_index < 0) {
                wifi_util_error_print(WIFI_APPS,"%s:%d MAC not connected not sounding \n", __func__, __LINE__);
                levl_sc_data = hash_map_get_next(p_map, levl_sc_data);
                tmp_data = hash_map_remove(p_map, mac_str);
                if (tmp_data != NULL) {
                    free(tmp_data);
                }
                continue;
            }

            memset(mac_addr, 0, sizeof(mac_address_t));
            memcpy(mac_addr, levl_sc_data->mac_addr, sizeof(mac_address_t));
            duration = levl_sc_data->duration;
            interval = levl_sc_data->interval;
            tmp_data = hash_map_remove(p_map, mac_str);
            if (tmp_data != NULL) {
                free(tmp_data);
                wifi_util_dbg_print(WIFI_APPS,
                    "pending map handoff mac:%02x..%02x\n",
                    mac_addr[0], mac_addr[5]);
                schedule_mac_for_sounding_locked(ap_index, mac_addr, duration, interval);
            }
            break;
        }
    }
    return 0;
}

/*
 * HANDLER: em_deinit
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c (already non-static).
 * Local array:
 *   - mac_addr_str_t mac_str (char[18]) : memset(sizeof) + bounded to_mac_str.
 * The function iterates the client-type hash map (freeing each entry) and the
 * pending-blocks list (freeing each node). mac_str is written only by
 * to_mac_str into its 18 bytes. No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): to_mac_str / hash_map_* / scheduler_cancel_timer_task
 * / wifi_hal_delHostapdDenyAclDevice / acl_block_end / get_wifictrl_obj are
 * stubbed. The client-type map is a small local store of malloc'd entries; the
 * pending-blocks list is kept empty (its cleanup is the head==NULL path).
 * Driven by the edi_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#define WIFI_EM 0
#ifndef wifi_util_dbg_print
#define wifi_util_info_print(m, ...)  do {} while (0)
#endif

/* --- pending-blocks types (cleanup path kept empty in the harness) --- */
typedef struct { int timer_id; int vap_index; char *kick_list; bool cancelled_by_unblock; } kick_details_t;
typedef struct pending_block_node { kick_details_t *kick_details; struct pending_block_node *next; } pending_block_node_t;
static pending_block_node_t *pending_blocks_head = NULL;
static pthread_mutex_t pending_blocks_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_vap_acl_lock = PTHREAD_MUTEX_INITIALIZER;

/* --- client-type map: small local store of malloc'd entries --- */
#define EDI_MAX 8
static sta_client_info_t *edi_entries[EDI_MAX];
static int edi_n;      /* number of entries */
static int edi_it;     /* iteration cursor */
void edi_store_build(int n)   /* build n malloc'd entries with distinct macs */
{
    edi_n = (n > EDI_MAX) ? EDI_MAX : n;
    for (int i = 0; i < edi_n; i++) {
        edi_entries[i] = (sta_client_info_t *)calloc(1, sizeof(sta_client_info_t));
        edi_entries[i]->mac_addr[0] = 0xA0; edi_entries[i]->mac_addr[5] = (unsigned char)i;
    }
}
static void *edi_get_first(void *m) { (void)m; edi_it = 0; return (edi_n > 0) ? edi_entries[0] : NULL; }
static void *edi_get_next(void *m, void *cur) { (void)m; (void)cur; edi_it++; return (edi_it < edi_n) ? edi_entries[edi_it] : NULL; }
static void *edi_remove(void *m, const char *key) { (void)m; (void)key; return (edi_it < edi_n) ? edi_entries[edi_it] : NULL; }
static void edi_destroy(void *m) { (void)m; edi_destroy_calls++; }
#define hash_map_get_first(m)      edi_get_first((m))
#define hash_map_get_next(m, c)    edi_get_next((m), (c))
#define hash_map_remove(m, k)      edi_remove((m), (k))
#define hash_map_destroy(m)        edi_destroy((m))

/* --- other scaffolding stubs --- */
static struct { struct { void *client_type_map; } sta_client_type; } client_type_info;
static wifi_ctrl_t *get_wifictrl_obj(void) { return (wifi_ctrl_t *)edi_ctrl_buf; }
static char *to_mac_str(mac_address_t mac, mac_addr_str_t key)
{
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
static void scheduler_cancel_timer_task(void *s, int id) { (void)s; (void)id; }
static int wifi_hal_delHostapdDenyAclDevice(int vap, const char *mac) { (void)vap; (void)mac; return RETURN_OK; }
static void acl_block_end(int vap) { (void)vap; }

/* ================= VERBATIM from wifi_em.c ================= */
int em_deinit(wifi_app_t *app)
{
    void *tmp_data = NULL;
    mac_addr_str_t mac_str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    (void)app;

    wifi_util_info_print(WIFI_EM, "%s:%d: em-app deinit\n", __func__, __LINE__);

    sta_client_info_t *t_sta_data = (sta_client_info_t *)hash_map_get_first(
        client_type_info.sta_client_type.client_type_map);
    while (t_sta_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str((unsigned char *)t_sta_data->mac_addr, mac_str);
        tmp_data = (sta_client_info_t *)hash_map_remove(
            client_type_info.sta_client_type.client_type_map, mac_str);
        if (tmp_data != NULL) {
            free(tmp_data);
        }
        t_sta_data = (sta_client_info_t *)hash_map_get_next(client_type_info.sta_client_type.client_type_map,
            t_sta_data);
    }
    hash_map_destroy(client_type_info.sta_client_type.client_type_map);

    // Cancel and free any pending block timers/entries before destroying the mutex
    pthread_mutex_lock(&pending_blocks_lock);
    pending_block_node_t *node = pending_blocks_head;
    pending_blocks_head = NULL;
    pthread_mutex_unlock(&pending_blocks_lock);

    while (node) {
        pending_block_node_t *next = node->next;
        if (node->kick_details) {
            if (node->kick_details->timer_id > 0) {
                scheduler_cancel_timer_task(ctrl->sched, node->kick_details->timer_id);
            }

            wifi_hal_delHostapdDenyAclDevice(node->kick_details->vap_index,
                node->kick_details->kick_list);

            acl_block_end(node->kick_details->vap_index);

            free(node->kick_details->kick_list);
            free(node->kick_details);
        }
        free(node);
        node = next;
    }

    pthread_mutex_destroy(&pending_blocks_lock);
    pthread_mutex_destroy(&g_vap_acl_lock);
    return RETURN_OK;
}

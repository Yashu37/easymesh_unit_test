/*
 * HANDLER: handle_sta_client_info
 *
 * Copied VERBATIM from OneWifi source/apps/em/wifi_em.c. Local array:
 *   - unsigned char client_mac[32] : written by to_mac_str(sta_info->mac_addr,
 *     client_mac) -- a 17-char mac string (+NUL), comfortably within 32.
 * The cache entry copy uses memcpy of sizeof(mac_address_t) and a strncpy
 * bounded by sizeof(client_type)-1 + explicit NUL. NULL input is rejected.
 * No array can be overrun -> SAFE.
 *
 * Scaffolding (NOT under test): to_mac_str is stubbed; hash_map_get/hash_map_put
 * are #define-redirected to a local single-entry store (frees the strdup'd
 * key). Driven by the hsci_* globals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#ifndef RETURN_OK
#define RETURN_OK  0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR (-1)
#endif
#define WIFI_EM 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#define wifi_util_error_print(m, ...) do {} while (0)
#endif

/* --- scaffolding stubs driven by hsci_* globals --- */
static char *to_mac_str(mac_address_t mac, unsigned char *key)
{
    snprintf((char *)key, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

/* local single-entry client-type map (isolates from the global hash map) */
static char  hsci_key[64];
static void *hsci_val;
static int   hsci_has_entry;
static void *hsci_hmget(void *m, const char *k) { (void)m; return (hsci_has_entry && strcmp(hsci_key, k) == 0) ? hsci_val : NULL; }
static int   hsci_hmput(void *m, char *k, void *d) { (void)m; snprintf(hsci_key, 64, "%s", k); hsci_val = d; hsci_has_entry = 1; free(k); return 0; }
#define hash_map_get(m, k)     hsci_hmget((m), (k))
#define hash_map_put(m, k, d)  hsci_hmput((m), (k), (d))
static struct { struct { void *client_type_map; } sta_client_type; } client_type_info;

void *hsci_store_get(void) { return hsci_val; }
void hsci_store_reset(void) { if (hsci_val) free(hsci_val); hsci_val = NULL; hsci_has_entry = 0; hsci_key[0] = 0; }
void hsci_store_prepopulate(const char *key) { hsci_store_reset(); snprintf(hsci_key, 64, "%s", key); hsci_val = calloc(1, sizeof(sta_client_info_t)); hsci_has_entry = 1; }

/* ================= VERBATIM from wifi_em.c ================= */
int handle_sta_client_info(wifi_app_t *app, void *data)
{
    (void)app;
    sta_client_info_t *sta_info = (sta_client_info_t *)data;
    unsigned char client_mac[32] = { 0 };
    sta_client_info_t *cli_data = NULL;

    if (sta_info == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d sta_info is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    to_mac_str(sta_info->mac_addr, client_mac);

    cli_data = (sta_client_info_t *)hash_map_get(
        client_type_info.sta_client_type.client_type_map, (const char *)client_mac);
    if (cli_data == NULL) {
        cli_data = (sta_client_info_t *)malloc(sizeof(sta_client_info_t));
        if (cli_data == NULL) {
            wifi_util_error_print(WIFI_EM, "%s:%d alloc failed for client type cache\n",
                __func__, __LINE__);
            return RETURN_ERR;
        }
        memset(cli_data, 0, sizeof(sta_client_info_t));
        memcpy(cli_data->mac_addr, sta_info->mac_addr, sizeof(mac_address_t));
        strncpy((char *)cli_data->client_type, (const char *)sta_info->client_type, sizeof(cli_data->client_type) - 1);
        cli_data->client_type[sizeof(cli_data->client_type) - 1] = '\0';

        hash_map_put(client_type_info.sta_client_type.client_type_map, strdup((const char *)client_mac),
            cli_data);
        wifi_util_dbg_print(WIFI_EM, "%s:%d Client Type Updated to stats cache [%s]\n",
            __func__, __LINE__, cli_data->client_type);
    } else {
        /* Refresh existing cache entry to avoid stale client type values. */
        strncpy((char *)cli_data->client_type, (const char *)sta_info->client_type, sizeof(cli_data->client_type) - 1);
        cli_data->client_type[sizeof(cli_data->client_type) - 1] = '\0';
    }

    return RETURN_OK;
}

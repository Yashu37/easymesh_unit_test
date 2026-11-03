/*
 * HANDLER: webconfig_harvester_apply
 *
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c (no
 * changes). Local array:
 *   - mac_address_t sta_mac (6 bytes): filled by harvester_str_to_mac_bytes
 *     (fixed 6-byte copy) and passed by value-pointer to monitor_enable_instant_msmt.
 * The decoded mac_address (char[13]) is read via strlen/sscanf/strncpy.
 * No array can be overrun for a NUL-terminated field -> SAFE.
 *
 * Scaffolding (NOT under test): the five sibling instant_msmt_* /
 * monitor_enable_instant_msmt functions are #define-redirected to local
 * recording stubs; harvester_str_to_mac_bytes is the real function.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define WIFI_HARVESTER 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...)   do {} while (0)
#endif

void harvester_str_to_mac_bytes(char *key, mac_addr_t bmac);
#define webconfig_subdoc_data_t wha_subdoc_data_t   /* shared harness type name (avoids clash with other TUs) */

static void wha_rep(int v) { (void)v; wha_rep_calls++; }
static void wha_def(int v) { (void)v; wha_def_calls++; }
static void wha_ttl(int v) { (void)v; wha_ttl_calls++; }
static void wha_mac(char *m) { (void)m; wha_mac_calls++; }
static void wha_en(unsigned char *mac, bool en) { wha_en_calls++; memcpy(wha_en_mac, mac, 6); wha_en_val = en; }
#define instant_msmt_reporting_period(v)   wha_rep(v)
#define instant_msmt_def_period(v)         wha_def(v)
#define instant_msmt_ttl(v)                wha_ttl(v)
#define instant_msmt_macAddr(m)            wha_mac(m)
#define monitor_enable_instant_msmt(m, e)  wha_en((unsigned char *)(m), (e))

/* ================= VERBATIM from wifi_harvester.c ================= */
void webconfig_harvester_apply(wifi_app_t *app, wifi_event_t *event)
{
    webconfig_subdoc_data_t *webconfig_data = NULL;
    webconfig_data = event->u.webconfig_data;
    wifi_util_dbg_print(WIFI_HARVESTER,"%s:%d Entering \n", __func__, __LINE__);

    mac_address_t sta_mac;

    instant_msmt_reporting_period(webconfig_data->u.decoded.harvester.u_inst_client_reporting_period);
    instant_msmt_def_period(webconfig_data->u.decoded.harvester.u_inst_client_def_reporting_period);
    instant_msmt_ttl(webconfig_data->u.decoded.harvester.u_inst_client_def_override_ttl);
    instant_msmt_macAddr(webconfig_data->u.decoded.harvester.mac_address);
    harvester_str_to_mac_bytes(webconfig_data->u.decoded.harvester.mac_address,sta_mac);
    monitor_enable_instant_msmt(sta_mac, webconfig_data->u.decoded.harvester.b_inst_client_enabled);
}

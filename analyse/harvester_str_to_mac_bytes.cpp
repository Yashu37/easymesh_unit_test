/*
 * HANDLER: harvester_str_to_mac_bytes
 * Copied VERBATIM from OneWifi source/apps/harvester/wifi_harvester.c.
 * Local array: unsigned int mac[6] -- sscanf writes exactly 6 unsigned ints
 * (six %02x conversions into &mac[0..5]); bmac[0..5] is a 6-byte copy into the
 * caller's mac_addr_t. Empty key returns early. No array overrun -> SAFE.
 * Scaffolding: wifi_util_dbg_print stub only. NO ASan calls here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

#define WIFI_HARVESTER 0
#ifndef wifi_util_dbg_print
#define wifi_util_dbg_print(m, ...) do {} while (0)
#endif

/* ================= VERBATIM from wifi_harvester.c ================= */
void harvester_str_to_mac_bytes (char *key, mac_addr_t bmac) {
    unsigned int mac[6];

    if (strlen(key) == 0) {
        wifi_util_dbg_print(WIFI_HARVESTER,"%s:%d: Input mac address is empty.\n", __func__, __LINE__);
        return;
    }

    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
               bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
               bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

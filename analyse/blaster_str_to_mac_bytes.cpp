/*
 * HANDLER: blaster_str_to_mac_bytes
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local array mac[6] (unsigned int) is filled by
 *   sscanf(key, "%02x:%02x:..", &mac[0..5])  (strlen(key) > MIN_MAC_LEN = 12)
 *   sscanf(key, "%02x%02x..",   &mac[0..5])  (otherwise)
 * and copied to bmac[0..5]. Indices are fixed 0..5, so mac[] cannot be
 * overrun. key is read by strlen/sscanf (must be NUL-terminated).
 *
 * The RUNNER poisons the caller's key past strlen(key)+1 and the caller's
 * bmac past MAC_ADDR_LEN (6). mac[6] is guarded by ASan stack redzones.
 *
 * Note: sscanf's return value is not checked; on a malformed key the
 * unfilled mac[] entries are uninitialised (garbage bytes, not an
 * out-of-bounds access).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define MIN_MAC_LEN 12                      /* wifi_blaster.c */
static void bsm_print(int module, const char *fmt, ...)
{
    char scratch[1024]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print    bsm_print
#define wifi_util_error_print  bsm_print

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c --- */
void blaster_str_to_mac_bytes (char *key, mac_addr_t bmac) {
    unsigned int mac[6];

    wifi_util_dbg_print(WIFI_BLASTER, "%s: value of key is %s and strlen of key is %d\n", __func__, key, strlen(key));

    if (strlen(key) == 0) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s:%d: Input mac address is empty.\n", __func__, __LINE__);
        return;
    }

    if(strlen(key) > MIN_MAC_LEN)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s: Entered in if\n", __func__);
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    }
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
               bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
               bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

    wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
}

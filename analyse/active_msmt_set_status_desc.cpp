/*
 * HANDLER: active_msmt_set_status_desc
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). No fixes.
 * Local mac[MAC_ADDRESS_LENGTH] (= 13):
 *   - strlen(dst_mac) != 12 : snprintf(mac, sizeof(mac), MAC_FMT_TRIMMED, MAC_ARG(dst_mac))
 *                             -> 12 hex chars + NUL (reads dst_mac[0..5]).
 *   - else                  : strncpy(mac, dst_mac, sizeof(mac) - 1).
 * Then snprintf(g_active_msmt->status_desc, 512, "Plan[%s] Step[%d] Mac[%s]
 *   FW[] Node[] Status[%s] %s", plan_id ?: "", step_id, mac, <status str>, msg ?: "").
 *
 * Redirect: snprintf() -> asd_snprintf(): real vsnprintf on a runner slot of
 * the SAME size (13 -> asd_slot_mac, 512 -> asd_slot_desc), then copied back.
 * The RUNNER poisons each slot past its size, the caller's dst_mac past 13
 * (= MAC_ADDRESS_LENGTH), and plan_id / msg past their NULs. mac is also
 * guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - get_wifi_blaster(): returns the runner's stand-in (status + status_desc).
 *   - active_msmt_status_to_str(): copied verbatim.
 *   - wifi_util_dbg_print(): really formats its arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define MAC_ADDRESS_LENGTH 13                        /* include/wifi_base.h */
#define MAC_FMT_TRIMMED "%02x%02x%02x%02x%02x%02x"   /* wifi_blaster.c */
#define MAC_ARG(arg) arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]

static void asd_dbg_print(int module, const char *fmt, ...)
{
    char scratch[1024]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print  asd_dbg_print

static void *get_wifi_blaster(void) { return asd_mgr_buf; }

/* copied verbatim from source/apps/blaster/wifi_blaster.c */
char *active_msmt_status_to_str(active_msmt_status_t status)
{
    switch (status)
    {
        case ACTIVE_MSMT_STATUS_SUCCEED:
            return "SUCCEED";
        case ACTIVE_MSMT_STATUS_CANCELED:
            return "CANCELED";
        case ACTIVE_MSMT_STATUS_FAILED:
            return "FAILED";
        case ACTIVE_MSMT_STATUS_BUSY:
            return "BUSY";
        case ACTIVE_MSMT_STATUS_NO_CLIENT:
            return "NO_CLIENT";
        case ACTIVE_MSMT_STATUS_SLEEP_CLIENT:
            return "SLEEP_CLIENT";
        case ACTIVE_MSMT_STATUS_WRONG_ARG:
            return "WRONG_ARG";
        default:
            return "UNDEFINED";
    }
}

/* redirect: write into a runner slot of the same size as the real array */
static int asd_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    char *slot = (sz == ASD_MAC_SZ) ? asd_slot_mac : asd_slot_desc;
    size_t cap = (sz == ASD_MAC_SZ) ? ASD_MAC_SZ : ASD_DESC_SZ;
    if (sz > cap) sz = cap;
    int r;
    va_list ap;
    memset(slot, 0, sz);
    va_start(ap, fmt);
    r = vsnprintf(slot, sz, fmt, ap);
    va_end(ap);
    memcpy(out, slot, sz);
    if (sz == ASD_MAC_SZ) asd_mac_len = strnlen(slot, sz);
    else                  asd_desc_len = strnlen(slot, sz);
    return r;
}
#define snprintf(o, n, ...)  asd_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
void active_msmt_set_status_desc(const char *func, unsigned char *plan_id, unsigned int step_id,
    unsigned char *dst_mac, char *msg)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    char mac[MAC_ADDRESS_LENGTH] = {};

    memset(&g_active_msmt->status_desc, 0, sizeof(g_active_msmt->status_desc));

    if (strlen((char *)dst_mac) != MAC_ADDRESS_LENGTH - 1) {
        snprintf(mac, sizeof(mac), MAC_FMT_TRIMMED, MAC_ARG(dst_mac));
    } else {
        strncpy(mac, (char *)dst_mac, sizeof(mac) - 1);
    }

    snprintf(g_active_msmt->status_desc, sizeof(g_active_msmt->status_desc),
        "Plan[%s] Step[%d] Mac[%s] FW[] Node[] Status[%s] %s",
        (char *)plan_id ?: "", step_id, mac, active_msmt_status_to_str(g_active_msmt->status), msg ?: "");

    wifi_util_dbg_print(WIFI_BLASTER, "%s: %s\n", func, g_active_msmt->status_desc);
}

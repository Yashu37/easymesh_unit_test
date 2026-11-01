/*
 * HANDLER: SetActiveMsmtStepSrcMac
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c.
 * No fixes. Local mac_address_t bmac (6 bytes) <- blaster_str_to_mac_bytes(
 * SrcMac, bmac) (indices 0..5), then memcpy'd into Step[StepIns].SrcMac.
 *
 * The RUNNER poisons the caller's SrcMac past its NUL and the g_active_msmt
 * stand-in past its size. bmac is also guarded by ASan stack redzones.
 *
 * Scaffolding (NOT the function under test): get_wifi_blaster() returns the
 * runner stand-in; blaster_str_to_mac_bytes() parses the MAC into bmac;
 * wifi_util_dbg_print() really formats its arguments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define ULONG unsigned long

static void ssm_print(int module, const char *fmt, ...)
{
    char scratch[1024]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
#define wifi_util_dbg_print  ssm_print

static void *get_wifi_blaster(void) { return ssm_mgr_buf; }

static void blaster_str_to_mac_bytes(char *key, unsigned char *bmac)
{
    unsigned int m[6] = {0};
    if (strlen(key) > 12)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    for (int i = 0; i < 6; i++) bmac[i] = (unsigned char)m[i];
}

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c --- */
void SetActiveMsmtStepSrcMac(char *SrcMac, ULONG StepIns)
{
    mac_address_t bmac;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Step Src Mac changed to %s for ins : %d\n", __func__, __LINE__,SrcMac,StepIns);
    blaster_str_to_mac_bytes(SrcMac, bmac);
    memset(g_active_msmt->active_msmt.Step[StepIns].SrcMac, 0, sizeof(mac_address_t));
    memcpy(g_active_msmt->active_msmt.Step[StepIns].SrcMac, bmac, sizeof(mac_address_t));
}

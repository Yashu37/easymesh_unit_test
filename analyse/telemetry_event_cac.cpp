/*
 * HANDLER: telemetry_event_cac
 *
 * Function copied VERBATIM from OneWifi source/apps/cac/wifi_cac.c. No fixes.
 * Local arrays telemetry_buff[64] and telemetry_val[128] are written only by
 *   snprintf(telemetry_buff, sizeof(telemetry_buff), "XWIFIS_%s_accum", deny_type)
 *   snprintf(telemetry_val,  sizeof(telemetry_val),  "%s,%s,%d,%d", deny_reason, mac, threshold, value)
 * (and the XWIFI_/6G variants) -- all bounded by sizeof.
 *
 * Redirect: snprintf() -> tec_snprintf(): real vsnprintf on a runner slot of
 * the SAME size (64 -> tec_slot_buff, 128 -> tec_slot_val), then copied back.
 * The RUNNER poisons each slot past its size and the caller's deny_type /
 * deny_reason / mac buffers past their NULs. The arrays are also ASan-stack
 * guarded.
 *
 * Scaffolding (NOT the function under test): the isVapHotspot* selectors,
 * wifi_util_info_print, and get_stubs_descriptor()->t2_event_s_fn are
 * file-local stubs; the selected band is chosen by tec_band.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_APPS 0

static void tec_print(int module, const char *fmt, ...)
{ char sc[512]; va_list ap; (void)module; va_start(ap, fmt); vsnprintf(sc, sizeof(sc), fmt, ap); va_end(ap); }
#define wifi_util_info_print  tec_print

static int isVapHotspotSecure5g(int i) { (void)i; return tec_band == 1; }
static int isVapHotspotOpen5g(int i)   { (void)i; return tec_band == 2; }
static int isVapHotspotSecure6g(int i) { (void)i; return tec_band == 3; }
static int isVapHotspotOpen6g(int i)   { (void)i; return tec_band == 4; }

typedef struct { void (*t2_event_s_fn)(char *, char *); } tec_stubs_t;
static void tec_t2(char *marker, char *val) { snprintf(tec_t2_marker, sizeof(tec_t2_marker), "%s", marker); snprintf(tec_t2_val, sizeof(tec_t2_val), "%s", val); tec_t2_calls++; }
static tec_stubs_t tec_stubs = { tec_t2 };
static tec_stubs_t *get_stubs_descriptor(void) { return &tec_stubs; }

static int tec_snprintf(char *out, size_t sz, const char *fmt, ...)
{
    char *slot = (sz == TEC_BUFF_SZ) ? tec_slot_buff : tec_slot_val;
    size_t cap = (sz == TEC_BUFF_SZ) ? TEC_BUFF_SZ : TEC_VAL_SZ;
    if (sz > cap) sz = cap;
    int r; va_list ap;
    memset(slot, 0, sz);
    va_start(ap, fmt); r = vsnprintf(slot, sz, fmt, ap); va_end(ap);
    memcpy(out, slot, sz);
    if (sz == TEC_BUFF_SZ) tec_buff_len = strnlen(slot, sz);
    else                   tec_val_len = strnlen(slot, sz);
    return r;
}
#define snprintf(o, n, ...)  tec_snprintf((o), (n), __VA_ARGS__)

/* --- copied verbatim from source/apps/cac/wifi_cac.c --- */
void telemetry_event_cac(char *deny_type,int index, char *deny_reason,char *mac,int threshold ,int value)
{
    char telemetry_buff[64] = {0};
    char telemetry_val[128] = {0};

    if (!deny_type || !deny_reason || !mac ) {
        return;
    }

    memset(telemetry_buff, 0, sizeof(telemetry_buff));
    memset(telemetry_val, 0, sizeof(telemetry_val));

    if (isVapHotspotSecure5g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFIS_%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else if (isVapHotspotOpen5g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFI_%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else if (isVapHotspotSecure6g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFIS_6G%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else if (isVapHotspotOpen6g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFI_6G%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else {
        return;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d telemetry_buff=%s and telemetry_val=%s\n", __func__, __LINE__,telemetry_buff,telemetry_val);
    get_stubs_descriptor()->t2_event_s_fn(telemetry_buff, telemetry_val);
}

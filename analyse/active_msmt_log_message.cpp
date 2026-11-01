/*
 * HANDLER: active_msmt_log_message
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). No fixes.
 * Local msg[1024] <- vsnprintf(msg, sizeof(msg), fmt, args). msg is then
 * handed to the CCSP trace hook and to wifi_util_dbg_print(WIFI_BLASTER, msg).
 *
 * Redirect: vsnprintf() -> aml_vsnprintf(): real vsnprintf on the runner
 * slot aml_slot (SAME size, 1024), then copied into msg. The RUNNER poisons
 * aml_slot past 1024, the caller's string argument past its NUL, and the
 * wifi_mgr_t stand-in past its size. msg is also guarded by ASan stack
 * redzones.
 *
 * Scaffolding (NOT the function under test):
 *   - get_wifimgr_obj(): returns the runner's wifi_mgr_t stand-in whose
 *     CcspTraceInfoRdkb_fn / CcspTraceDebugRdkb_fn record the message.
 *   - wifi_util_dbg_print(): records its formatted output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0

void aml_dbg_print(int module, const char *format, ...)
{
    (void)module;
    snprintf(aml_dbg_out, sizeof(aml_dbg_out), "%s", format);   /* records msg as-is */
}
#define wifi_util_dbg_print  aml_dbg_print

static void *get_wifimgr_obj(void) { return aml_mgr_buf; }

static int aml_vsnprintf(char *out, size_t sz, const char *fmt, va_list ap)
{
    if (sz > AML_SLOT_SZ) sz = AML_SLOT_SZ;
    memset(aml_slot, 0, sz);
    int r = vsnprintf(aml_slot, sz, fmt, ap);
    memcpy(out, aml_slot, sz);
    aml_msg_len = strnlen(aml_slot, sz);
    return r;
}
#define vsnprintf(o, n, f, a)  aml_vsnprintf((o), (n), (f), (a))

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
void active_msmt_log_message( blaster_log_level_t level,char *fmt, ...)
{
    va_list args;
    char msg[1024] = {};
    wifi_mgr_t *wifi_mgr = (wifi_mgr_t *) get_wifimgr_obj();

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    switch(level){
    case BLASTER_INFO_LOG:
        wifi_mgr->wifi_ccsp.desc.CcspTraceInfoRdkb_fn(msg);
        break;
    case BLASTER_DEBUG_LOG:
        wifi_mgr->wifi_ccsp.desc.CcspTraceDebugRdkb_fn(msg);
        break;
    default:
        break;
}

    wifi_util_dbg_print(WIFI_BLASTER, msg);
}

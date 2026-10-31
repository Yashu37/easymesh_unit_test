/*
 * HANDLER: logger_traceback_log
 *
 * Function copied VERBATIM from OneWifi lib/log/log_traceback.c. No fixes.
 * The static ring msgs[32][1024] is indexed only via % ARRAY_SIZE(msgs)
 * (0..31) and filled with bounded snprintf, so no array OOB is possible.
 * Caller inputs msg->lm_tag / lm_text are poisoned by the runner; msgs is
 * internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test): LOG_MODULE_ID_TRACEBACK /
 * LOG_SEVERITY_WARNING defines, ARRAY_SIZE, UNREFERENCED_PARAMETER, and a
 * file-local mlog() stub (the real mlog is exercised by its own harness).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define LOG_MODULE_ID_TRACEBACK 99
#define LOG_SEVERITY_WARNING    4

extern int tb_flush_count;   /* bumped by the mlog stub (flush path) */
static void mlog(int sev, int mod, const char *fmt, ...)
{
    (void)sev; (void)mod; (void)fmt;
    tb_flush_count++;
}

/* --- copied verbatim from lib/log/log_traceback.c --- */
void
logger_traceback_log(logger_t *l, logger_msg_t *msg)
{
    UNREFERENCED_PARAMETER(l);
    static char msgs[32][1024];
    static size_t cur = 0;
    size_t i, j;

    if (msg->lm_module == LOG_MODULE_ID_TRACEBACK)
        return;

    if (msg->lm_severity <= LOG_SEVERITY_WARNING) {
        for (i = 0; i < ARRAY_SIZE(msgs); i++) {
            j = (cur + i) % ARRAY_SIZE(msgs);
            if (*msgs[j])
                mlog(msg->lm_severity, LOG_MODULE_ID_TRACEBACK, "%s", msgs[j]);
            *msgs[j] = 0;
        }
        return;
    }

    snprintf(msgs[cur], sizeof(msgs[cur]), "%s: %s", msg->lm_tag, msg->lm_text);
    cur++;
    cur %= ARRAY_SIZE(msgs);
}

/*
 * HANDLER: mlog
 *
 * Function copied VERBATIM from OneWifi lib/log/log.c. No fixes.
 * Three local arrays, all bounded:
 *   - buff[LOGGER_BUFF_LEN=8192]: vsnprintf(buff, sizeof, fmt, args)
 *   - timestr[80]: strftime(timestr, sizeof, ...)
 *   - se_tag[64]: snprintf(se_tag, sizeof, ...)
 * Note: on an EMPTY fmt, "strip = &buff[strlen(buff)-1]" computes buff-1,
 * but the while guard (strip > buff) is false so it is never dereferenced
 * (tested by the empty_fmt case).
 *
 * Scaffolding (NOT the function under test): severity/module tables and
 * their lookups, log_enabled, log_any_sink_match, time_real, and the
 * ds_dlist logger list are stubbed. The logger list is EMPTY, so the
 * ds_dlist_foreach loop runs zero times while the three arrays are still
 * formatted -- which is what the harness observes. fmt is poisoned by the
 * runner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding: defines/types from lib/log/log.c/.h --- */
#define LF '\n'
#define CR '\r'
#define NUL '\0'
#define LOGGER_BUFF_LEN (1024 * 8)
#define LOG_NAME_LEN 80

typedef enum { LOG_SEVERITY_DISABLED = 0, LOG_SEVERITY_INFO, LOG_SEVERITY_ERR,
               LOG_SEVERITY_DEBUG, LOG_SEVERITY_LAST } log_severity_t;
typedef enum { LOG_MODULE_ID_MISC = 0, LOG_MODULE_ID_WIFI, LOG_MODULE_ID_LAST } log_module_t;

typedef struct { log_severity_t s; char *name; char *color; } log_severity_entry_t;
typedef struct { log_module_t module; char module_name[LOG_NAME_LEN]; log_severity_t severity; } log_module_entry_t;

static log_severity_entry_t log_severity_table[LOG_SEVERITY_LAST] = {
    { LOG_SEVERITY_DISABLED, (char *)"OFF",   (char *)"" },
    { LOG_SEVERITY_INFO,     (char *)"INFO",  (char *)"" },
    { LOG_SEVERITY_ERR,      (char *)"ERR",   (char *)"" },
    { LOG_SEVERITY_DEBUG,    (char *)"DEBUG", (char *)"" },
};
static log_module_entry_t log_module_table[LOG_MODULE_ID_LAST] = {
    { LOG_MODULE_ID_MISC, "MISC", LOG_SEVERITY_DEBUG },
    { LOG_MODULE_ID_WIFI, "WIFI", LOG_SEVERITY_DEBUG },
};

static bool log_enabled = true;
static bool log_any_sink_match(log_severity_t sev, log_module_t module) { (void)sev; (void)module; return true; }
static time_t time_real(void) { return time(NULL); }

/* a 1-element logger list: the registered logger_fn captures the formatted
 * message so the test can verify buff/timestr/se_tag content. */
extern int  mlog_captured;
extern char mlog_captured_text[8300];
extern char mlog_captured_tag[128];
static void mlog_cb(logger_t *self, logger_msg_t *msg)
{
    (void)self;
    mlog_captured = 1;
    snprintf(mlog_captured_text, 8300, "%s", msg->lm_text);
    snprintf(mlog_captured_tag, 128, "%s", msg->lm_tag);
}
typedef struct { void *od_head; } ds_dlist_t;
static ds_dlist_t log_logger_list = { NULL };
static logger_t g_logger = { mlog_cb, NULL };
static logger_t *ds_dlist_head(ds_dlist_t *l) { (void)l; return &g_logger; }
static logger_t *ds_dlist_next(ds_dlist_t *l, logger_t *p) { (void)l; (void)p; return NULL; }
#define ds_dlist_foreach(list, p) for (p = ds_dlist_head(list); p != NULL; p = ds_dlist_next(list, p))

/* --- copied verbatim from lib/log/log.c (extern "C" so the test can call
 *     it with int sev/module instead of the local enums) --- */
extern "C" void mlog(log_severity_t sev,
          log_module_t module,
          const char  *fmt, ...)
{
    char            buff[LOGGER_BUFF_LEN];
    char            timestr[80];
    struct tm             *lt;
    time_t                 t;
    va_list                args;
    char           *strip;
    log_severity_entry_t *se;
    char           *tag;

    // Save errno, so that log does not overwrite it
    int save_errno = errno;

    if (false == log_enabled) {
        return;
    }

    if (sev == LOG_SEVERITY_DISABLED) {
        return;
    }

    if (module >= LOG_MODULE_ID_LAST) module = LOG_MODULE_ID_MISC;

    if (!log_any_sink_match(sev, module)) {
        return;
    }

    se = &log_severity_table[sev];
    tag = log_module_table[module].module_name;
    t = time_real();
    lt = localtime(&t);

    strftime(timestr, sizeof(timestr), "%d %b %H:%M:%S %Z", lt);

    // format
    va_start(args, fmt);
    vsnprintf(buff, sizeof(buff), fmt, args);
    va_end(args);

    // chop \r\n
    strip = &buff[strlen(buff) - 1];
    while ((strip > buff) && ((*strip == LF) || (*strip == CR)))
        *strip = NUL;

    // pretty print
    char se_tag[64];
    char *spaces = (char *)"          ";
    size_t se_len = 16;
    int scnt = 1;

    if ((strlen(se->name) + strlen(tag) + 2) < se_len) {
        scnt = se_len - (strlen(se->name) + strlen(tag) + 2);
    }

    snprintf(se_tag, sizeof(se_tag), "<%s>%.*s%s", se->name, scnt, spaces, tag);

    /* Craft the message */
    logger_msg_t msg;

    msg.lm_severity = sev;
    msg.lm_module = module;
    msg.lm_module_name = log_module_table[module].module_name;
    msg.lm_tag = se_tag;
    msg.lm_timestamp = timestr;
    msg.lm_text = buff;

    /* Feed messages to the registered loggers */
    logger_t *plog;
    ds_dlist_foreach(&log_logger_list, plog)
    {
        if (plog->match_fn) {
            if (!plog->match_fn(sev, module)) continue;
        } else {
            if (sev > log_module_table[module].severity) continue;
        }
        plog->logger_fn(plog, &msg);
    }

    // restore saved errno value
    errno = save_errno;

    return;
}

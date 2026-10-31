/*
 * HANDLER: log_severity_parse_sink
 *
 * Function copied VERBATIM from OneWifi lib/log/log.c. No fixes.
 * Local psevstr[LOG_SEVERITY_STR_MAX] is written only after the guards
 * (sevstr != NULL and strlen(sevstr) < LOG_SEVERITY_STR_MAX) via STRSCPY
 * (bounded), so it cannot overflow. The caller input sevstr is poisoned by
 * the runner; psevstr is internal (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test): the _log_sink_* sink helpers,
 * log_severity_fromstr/str, log_module_fromstr/str, the severity/module
 * enums, STRSCPY+strscpy, and LOG are all stubbed/copied so the verbatim
 * body compiles and parses realistically.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)
#define LOG_SEVERITY_STR_MAX 256
typedef enum { LOG_SINK_LOCAL = 0, LOG_SINK_REMOTE = 1 } log_sink_t;
typedef enum { SEV_DEBUG, SEV_INFO, SEV_ERR, LOG_SEVERITY_LAST } log_severity_t;
typedef enum { MOD_WIFI, MOD_CORE, LOG_MODULE_ID_LAST } log_module_t;

#define ASSERT_ARRAY(A) A
#define STRSCPY(dest, src) strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))
static ssize_t strscpy(char *dest, const char *src, size_t size)
{
    size_t len;
    if (size == 0) return -E2BIG;
    len = strnlen(src, size - 1);
    memcpy(dest, src, len);
    dest[len] = 0;
    if (src[len]) return -E2BIG;
    return (ssize_t)len;
}

/* record of what the stubbed sink setters received (for the test to inspect) */
int lsp_default_set, lsp_sev_set, lsp_mod_sev_set;

static void _log_sink_severity_set_default(log_sink_t s) { (void)s; lsp_default_set++; }
static void _log_sink_get(log_sink_t s, char **name) { (void)s; static char *n = (char *)"SINK: "; *name = n; }
static void _log_sink_severity_set(log_sink_t s, log_severity_t sev) { (void)s; (void)sev; lsp_sev_set++; }
static void _log_sink_module_severity_set(log_sink_t s, log_module_t m, log_severity_t sev) { (void)s; (void)m; (void)sev; lsp_mod_sev_set++; }

static log_severity_t log_severity_fromstr(const char *s)
{
    if (!strcmp(s, "DEBUG")) return SEV_DEBUG;
    if (!strcmp(s, "INFO"))  return SEV_INFO;
    if (!strcmp(s, "ERR"))   return SEV_ERR;
    return LOG_SEVERITY_LAST;
}
static const char *log_severity_str(log_severity_t sev)
{
    switch (sev) { case SEV_DEBUG: return "DEBUG"; case SEV_INFO: return "INFO";
                   case SEV_ERR: return "ERR"; default: return "?"; }
}
static log_module_t log_module_fromstr(const char *s)
{
    if (!strcmp(s, "wifi")) return MOD_WIFI;
    if (!strcmp(s, "core")) return MOD_CORE;
    return LOG_MODULE_ID_LAST;
}
static const char *log_module_str(log_module_t m)
{
    switch (m) { case MOD_WIFI: return "wifi"; case MOD_CORE: return "core"; default: return "?"; }
}

/* --- copied verbatim from lib/log/log.c (extern "C" so the test can call
 *     it without naming the local log_sink_t enum) --- */
extern "C" bool log_severity_parse_sink(log_sink_t sink, char *sevstr)
{
    char    psevstr[LOG_SEVERITY_STR_MAX];
    char   *tsevstr;
    char   *token;
    char   *sink_name;

    // start with default then apply parsed settings
    _log_sink_severity_set_default(sink);
    _log_sink_get(sink, &sink_name);

    if (sevstr == NULL) return false;

    if (strlen(sevstr) >= LOG_SEVERITY_STR_MAX)
    {
        LOG(ERR, "Severity string is too long.");
        return false;
    }

    STRSCPY(psevstr, sevstr);

    token = strtok_r(psevstr, ", ", &tsevstr);

    while (token != NULL)
    {
        log_severity_t sev;
        log_module_t       mod;

        char *arg1 = NULL;
        char *arg2 = NULL;


        arg1 = token;
        arg2 = strchr(token, ':');

        if (arg2 == NULL)
        {
            sev = log_severity_fromstr(arg1);

            if (sev != LOG_SEVERITY_LAST)
            {
                LOG(NOTICE, "%sDefault severity set: %s", sink_name, log_severity_str(sev));
                _log_sink_severity_set(sink, sev);
            }
            else
            {
                LOG(ERR, "Invalid default severity: %s", arg1);
                return false;
            }
        }
        else
        {
            *arg2++ = '\0';

            mod = log_module_fromstr(arg1);
            sev = log_severity_fromstr(arg2);

            if (sev != LOG_SEVERITY_LAST && mod != LOG_MODULE_ID_LAST)
            {
                LOG(NOTICE, "%sModule log severity changed. module=%s|severity=%s",
                        sink_name, log_module_str(mod), log_severity_str(sev));

                _log_sink_module_severity_set(sink, mod, sev);
            }
            else
            {
                LOG(ERR, "Invalid module severity. module=%s|severity=%s", arg1, arg2);
                return false;
            }
        }

        token = strtok_r(NULL, ", ", &tsevstr);
    }

    return true;
}

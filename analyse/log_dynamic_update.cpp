/*
 * HANDLER: log_dynamic_update
 *
 * Function copied VERBATIM from OneWifi lib/log/log.c (static there; made
 * extern here). No fixes. Local arrays:
 *   - new_severity[256], remote_severity[256]: filled by
 *     log_dynamic_state_parse_severity(..., buf, sizeof(buf)) (size-bounded)
 *   - remote_name[64]: filled by snprintf(..., sizeof, "%s_%s", ...) (bounded)
 * All are internal, auto-guarded by ASan.
 *
 * Scaffolding (NOT the function under test): jansson json_load_file /
 * json_decref, log_dynamic_state_parse_severity and
 * log_set_severity_if_changed are STUBBED (the real ones need jansson + log
 * internals). The parse stub writes a severity bounded by the size it is
 * given, exactly like the real function. log_dynamic/log_name globals and
 * the #defines mirror lib/log/log.c/.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
#define LOGT(...) do { } while (0)
#define LOGD(...) do { } while (0)
#define LOG_SEVERITY_STR_MAX 256
#define LOG_DEFAULT_ENTRY  "DEFAULT"
#define LOG_DEFAULT_REMOTE "REMOTE"
typedef enum { LOG_SINK_LOCAL = 0, LOG_SINK_REMOTE = 1 } log_sink_t;
typedef struct json_fake json_t;

static struct {
    const char *state_file_path;
} log_dynamic = { "/tmp/does_not_matter.json" };
static const char *log_name = "OneWifi";

/* test knobs (defined in the construct file) */
extern int         ldu_json_ok;       /* json_load_file returns non-NULL? */
extern const char *ldu_sev_value;     /* severity the parse stub writes */
extern int         ldu_parse_trigger; /* value parse writes to *new_trigger (local) */
extern char        ldu_last_local[320];
extern char        ldu_last_remote[320];

static json_t *json_load_file(const char *path, int flags, void *err)
{
    (void)path; (void)flags; (void)err;
    return ldu_json_ok ? (json_t *)1 : NULL;   /* opaque non-NULL on success */
}
static void json_decref(json_t *j) { (void)j; }

static bool log_dynamic_state_parse_severity(json_t *loggers_json,
        const char *name, const char *default_name,
        int *new_trigger, char *new_severity, int new_severity_len)
{
    (void)loggers_json; (void)name; (void)default_name;
    if (new_trigger) *new_trigger = ldu_parse_trigger;
    snprintf(new_severity, new_severity_len, "%s", ldu_sev_value);  /* bounded, like the real one */
    return true;
}
static void log_set_severity_if_changed(log_sink_t sink, char *new_severity)
{
    /* record what each sink received so the test can inspect it */
    if (sink == LOG_SINK_LOCAL)  snprintf(ldu_last_local,  sizeof(ldu_last_local),  "%s", new_severity);
    else                         snprintf(ldu_last_remote, sizeof(ldu_last_remote), "%s", new_severity);
}

/* --- copied verbatim from lib/log/log.c --- */
bool log_dynamic_update(int *new_trigger)
{
    *new_trigger = 0;
    char new_severity[LOG_SEVERITY_STR_MAX] = "";
    char remote_severity[LOG_SEVERITY_STR_MAX] = "";

    if (!log_dynamic.state_file_path) {
        return false;
    }
    LOGT("Re-reading logging state file %s.", log_dynamic.state_file_path);

    json_t *loggers_json = json_load_file(log_dynamic.state_file_path, 0, NULL);
    if (!loggers_json) {
        LOGD("Unable to read dynamic log state!");
        goto out;
    }

    // local
    log_dynamic_state_parse_severity(loggers_json, log_name, LOG_DEFAULT_ENTRY,
            new_trigger, new_severity, sizeof(new_severity));

    // remote
    char remote_name[64];
    snprintf(remote_name, sizeof(remote_name), "%s_%s", LOG_DEFAULT_REMOTE, log_name);
    log_dynamic_state_parse_severity(loggers_json, remote_name, LOG_DEFAULT_REMOTE,
            NULL, remote_severity, sizeof(remote_severity));

    json_decref(loggers_json);

out:
    log_set_severity_if_changed(LOG_SINK_LOCAL, new_severity);
    log_set_severity_if_changed(LOG_SINK_REMOTE, remote_severity);

    return true;
}

/* let the construct file point log_name at a test value (incl. very long) */
void ldu_set_log_name(const char *name) { log_name = name; }

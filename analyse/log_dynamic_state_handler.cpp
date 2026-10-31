/*
 * HANDLER: log_dynamic_state_handler
 *
 * Function copied VERBATIM from OneWifi lib/log/log.c (static there; made
 * extern here). No fixes. Its only array, full_path[LOG_TRIGGER_DIR_MAX*2],
 * is filled by log_dynamic_full_path_get(full_path, sizeof(full_path))
 * (bounded). It is an internal array (auto-guarded by ASan); the libev
 * callback params are unreferenced.
 *
 * Scaffolding (NOT the function under test): empty ev_loop/ev_stat stubs
 * (params unused); a log_dynamic struct with the three fields the function
 * reads; log_dynamic_update STUBBED via test knobs; log_dynamic_full_path_get
 * reused (extern, verbatim copy in its own harness file); LOGN/LOGE no-ops.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)
#define LOG_TRIGGER_DIR_MAX 128
#define LOGN(...) do { } while (0)
#define LOGE(...) do { } while (0)
/* struct ev_loop / ev_stat come from common.h */

static struct {
    const char *trigger_directory;
    int         trigger_value;
    void      (*trigger_callback)(FILE *fp);
} log_dynamic;

/* test knobs (defined in the construct file) */
extern int lds_update_ret;      /* what log_dynamic_update returns */
extern int lds_new_trigger;     /* value it writes to *new_trigger */
extern int lds_cb_count;        /* incremented by the trigger callback */

/* reused array-writer (verbatim copy lives in log_dynamic_full_path_get.cpp) */
extern void log_dynamic_full_path_get(char *buf, int len);

static bool log_dynamic_update(int *new_trigger)
{
    *new_trigger = lds_new_trigger;
    return lds_update_ret ? true : false;
}

static void lds_trigger_cb(FILE *fp) { (void)fp; lds_cb_count++; }

/* set up log_dynamic from the test knobs before each call */
void lds_setup(const char *dir, int trigger_value, int have_cb)
{
    log_dynamic.trigger_directory = dir;
    log_dynamic.trigger_value     = trigger_value;
    log_dynamic.trigger_callback  = have_cb ? lds_trigger_cb : NULL;
}

/* --- copied verbatim from lib/log/log.c --- */
void log_dynamic_state_handler(struct ev_loop *loop,
                                      ev_stat *watcher,
                                      int revents)
{
    UNREFERENCED_PARAMETER(loop);
    UNREFERENCED_PARAMETER(watcher);
    UNREFERENCED_PARAMETER(revents);

    int     new_trigger;

    if (!log_dynamic_update(&new_trigger)) {
        return;
    }

    if (log_dynamic.trigger_callback &&
        log_dynamic.trigger_directory &&
        new_trigger &&
        new_trigger > log_dynamic.trigger_value)
    {
        char full_path[LOG_TRIGGER_DIR_MAX * 2];
        log_dynamic_full_path_get(full_path, sizeof(full_path));

        LOGN("Module requested to dump information into %s", full_path);

        FILE *fp = fopen(full_path, "w");
        if (fp) {
            log_dynamic.trigger_callback(fp);
            fclose(fp);
        } else {
            LOGE("Unable to open file %s for dumping information! [%s]",
                 full_path, strerror(errno));
        }
    }

    log_dynamic.trigger_value = new_trigger;
}

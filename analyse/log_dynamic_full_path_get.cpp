/*
 * HANDLER: log_dynamic_full_path_get
 *
 * Function copied VERBATIM from OneWifi lib/log/log.c (static there; made
 * extern here so the test TU can call it). No fixes.
 *
 * Local timestamp[64] is filled by bounded strftime; the caller's buf is
 * written via bounded snprintf(buf, len, ...). The harness poisons buf past
 * len; timestamp[64] is internal (auto-guarded by ASan).
 *
 * Scaffolding: minimal log_dynamic (just trigger_directory) and log_name
 * globals, matching lib/log/log.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding: globals from lib/log/log.c --- */
static struct {
    const char *trigger_directory;
} log_dynamic = { "/tmp/logdump" };
static const char *log_name = "OneWifi";

/* --- copied verbatim from lib/log/log.c --- */
void log_dynamic_full_path_get(char *buf, int len)
{
    time_t now;
    struct tm ts;
    time(&now);
    ts = *localtime(&now);

    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &ts);

    // Create full path
    //   <directory>/<name>-<timestamp>.dump
    snprintf(buf, len, "%s/%s-%s.dump",
             log_dynamic.trigger_directory,
             log_name,
             timestamp);
}

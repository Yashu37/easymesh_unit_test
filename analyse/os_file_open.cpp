/*
 * HANDLER: os_file_open
 *
 * Function copied VERBATIM from OneWifi lib/osa/os_file_ops.c. No fixes.
 * Local arrays file[64] and time_stamp[32] are written via snprintf and the
 * size-bounded helpers os_pid_to_name()/os_time_stamp(); every append uses
 * sizeof(file) - strlen(file), so they stay bounded. Caller inputs location
 * and prefix are poisoned by the runner; file/time_stamp are internal
 * (auto-guarded by ASan).
 *
 * Scaffolding (NOT the function under test): os_pid_to_name and
 * os_time_stamp are stubbed (bounded writes, like the real ones); LOG no-op.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "common.h"
#include <sanitizer/asan_interface.h>

/* --- scaffolding --- */
enum { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG, TRACE };
#define LOG(sev, ...) do { } while (0)

static int os_pid_to_name(int32_t pid, char *buf, size_t sz)
{
    snprintf(buf, sz, "proc%d", pid);   /* bounded, like the real one */
    return 0;
}
static void os_time_stamp(char *buf, size_t sz)
{
    snprintf(buf, sz, "20261101-120000"); /* bounded */
}

/* --- copied verbatim from lib/osa/os_file_ops.c --- */
FILE *os_file_open(char *location, char *prefix)
{
    char file[64], time_stamp[32];
    FILE *fp;
    int32_t pid = getpid();


    memset(file, 0x00, sizeof(file));
    snprintf(file, sizeof(file), "%s/%s_", location, prefix);

    if (os_pid_to_name(pid, file + strlen(file), sizeof(file) - strlen(file)) != 0) {
        LOG(ERR, "Error! os_pid_to_name() failed");
        return NULL;
    }

    memset(time_stamp, 0x00, sizeof(time_stamp));
    os_time_stamp(time_stamp, sizeof(time_stamp));

    snprintf(file + strlen(file),
             sizeof(file) - strlen(file), "_%s.%d", time_stamp, pid);

    fp = fopen(file, "w+");
    if (NULL == fp)
        LOG(ERR, "Error opening the file: %s", file);

    return fp;
}

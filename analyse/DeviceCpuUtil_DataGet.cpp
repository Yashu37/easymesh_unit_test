/*
 * HANDLER: DeviceCpuUtil_DataGet
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). Local arrays:
 *   - buff[256]  <- fgets(buff, sizeof(buff), fp)
 *   - token[] = "cpu " (5 bytes) read by strncmp(buff, token, sizeof(token) - 1)
 *
 * Redirects: fopen(LINUX_PROC_STAT_FILE) opens the runner's temp file
 * (dcu_path); fgets() -> dcu_fgets(): real fgets into the runner slot
 * dcu_slot (SAME size, 256), then copied into buff. The RUNNER poisons
 * dcu_slot past 256 and the caller's util_cpu past sizeof(unsigned int).
 * buff/token are also guarded by ASan stack redzones.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define LINUX_PROC_STAT_FILE  dcu_path          /* real: "/proc/stat" */
static void wifi_util_dbg_print(int module, const char *fmt, ...)
{
    char scratch[1024]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
static char *dcu_fgets(char *out, int sz, FILE *fp)
{
    if (sz > DCU_SLOT_SZ) sz = DCU_SLOT_SZ;
    memset(dcu_slot, 0, sz);
    char *r = fgets(dcu_slot, sz, fp);
    memcpy(out, dcu_slot, sz);
    dcu_lines++;
    return r ? out : NULL;
}
#define fgets(o, n, f)  dcu_fgets((o), (n), (f))

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
bool DeviceCpuUtil_DataGet(unsigned int *util_cpu)
{
    FILE *fp;
    char buff[256] = {};
    char token[] = "cpu ";
    uint64_t hz_user, hz_nice, hz_system, hz_idle;
    static uint64_t prev_hz_user, prev_hz_nice, prev_hz_system, prev_hz_idle;
    static bool init = true;
    uint64_t hz_total;
    double busy;

    if ((fp = fopen(LINUX_PROC_STAT_FILE, "r")) == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "Failed to open file: %s\n", LINUX_PROC_STAT_FILE);
        *util_cpu = 0;
        return false;
    }

    while (fgets(buff, sizeof(buff), fp) != NULL) {

        if (strncmp(buff, token, sizeof(token) - 1) != 0) {
            continue;
        }

        sscanf(buff, "cpu %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64, &hz_user, &hz_nice, &hz_system, &hz_idle);

        if (init == true) {

            *util_cpu = 0;
            prev_hz_user = hz_user;
            prev_hz_nice = hz_nice;
            prev_hz_system = hz_system;
            prev_hz_idle = hz_idle;
            init = false;

            break;
        }

        hz_total = (hz_user - prev_hz_user) + (hz_nice - prev_hz_nice) + (hz_system - prev_hz_system) + (hz_idle - prev_hz_idle);

        if (hz_total == 0) {
            *util_cpu = 0;
            break;
        }

        busy = (1.0 - ((double)(hz_idle - prev_hz_idle) / (double)hz_total)) * 100.0;
        *util_cpu = (unsigned int) (busy + 0.5);

        prev_hz_user = hz_user;
        prev_hz_nice = hz_nice;
        prev_hz_system = hz_system;
        prev_hz_idle = hz_idle;

        break;
    }

    fclose(fp);
    return true;
}

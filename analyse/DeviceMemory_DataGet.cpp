/*
 * HANDLER: DeviceMemory_DataGet
 *
 * Function copied VERBATIM from OneWifi source/apps/blaster/wifi_blaster.c
 * (only "static" dropped so the runner can call it). No fixes. Local
 * buf[256] <- fgets(buf, sizeof(buf), proc_file); parsed with sscanf for
 * "MemTotal:" / "MemFree:". *util_mem = mem_total - mem_free.
 *
 * Redirect: fopen(LINUX_PROC_MEMINFO_FILE) opens the runner's temp file
 * (dmg_path); fgets() -> dmg_fgets(): real fgets into the runner slot
 * dmg_slot (SAME size, 256), then copied into buf. The RUNNER poisons
 * dmg_slot past 256 and the caller's util_mem past sizeof(uint32_t).
 * buf is also guarded by ASan stack redzones.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "common.h"

/* --- scaffolding --- */
#define WIFI_BLASTER 0
#define LINUX_PROC_MEMINFO_FILE  dmg_path          /* real: "/proc/meminfo" */
static void wifi_util_dbg_print(int module, const char *fmt, ...)
{
    char scratch[1024]; va_list ap; (void)module;
    va_start(ap, fmt); vsnprintf(scratch, sizeof(scratch), fmt, ap); va_end(ap);
}
static char *dmg_fgets(char *out, int sz, FILE *fp)
{
    if (sz > DMG_SLOT_SZ) sz = DMG_SLOT_SZ;
    memset(dmg_slot, 0, sz);
    char *r = fgets(dmg_slot, sz, fp);
    memcpy(out, dmg_slot, sz);
    dmg_lines++;
    return r ? out : NULL;
}
#define fgets(o, n, f)  dmg_fgets((o), (n), (f))

/* --- copied verbatim from source/apps/blaster/wifi_blaster.c (only "static" dropped) --- */
bool DeviceMemory_DataGet(uint32_t *util_mem)
{
    const char *filename = LINUX_PROC_MEMINFO_FILE;
    FILE *proc_file = NULL;
    char buf[256] = {'\0'};
    uint32_t mem_total = 0;
    uint32_t mem_free = 0;

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"Failed opening file: %s\n", filename);
        return false;
    }

    while (fgets(buf, sizeof(buf), proc_file) != NULL)
    {
        if (strncmp(buf, "MemTotal:", strlen("MemTotal:")) == 0)
        {
            if (sscanf(buf, "MemTotal: %u", &mem_total) != 1)
                goto parse_error;
        } else if (strncmp(buf, "MemFree:", strlen("MemFree:")) == 0) {
            if (sscanf(buf, "MemFree: %u", &mem_free) != 1)
                goto parse_error;
        }
    }
    wifi_util_dbg_print(WIFI_BLASTER," Returned MemTotal is %d and MemFree is %d\n", mem_total, mem_free);
    *util_mem = mem_total - mem_free;
    fclose(proc_file);
    return true;

parse_error:
    fclose(proc_file);
    wifi_util_dbg_print(WIFI_BLASTER,"Error parsing %s.\n", filename);
    return false;
}

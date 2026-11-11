/*
 * HANDLER: wifi_dpp_dbg_print (src/wifi_hal_dpp.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1 and fix 2): src/wifi_hal_dpp.c:110-139 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fixes 1-2 applied (start fix n / end fix n markers; the unfixed copy is the reproducer).  When /nvram/wifiDppDbg is readable it builds
 * "<formatted time> <message>" in the local buff[2048] with strcat + vsprintf, opens /tmp/wifiDPP once into a function-static FILE * and appends the text.
 *
 * Scaffolding only: access() and fopen() are the runner-controlled stubs of hwr_wdb.h (macros below), get_formatted_time is a deterministic stand-in writing HWR_WDB_TS; fputs / fflush / strcat / vsprintf
 * are the real libc functions; renamed hwr_sg_wifi_dpp_dbg_print.
 */
#include "hwr_wdb.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

hwr_wdb_world_t hwr_wdb_world;
static int hwr_wdb_access(const char *path, int mode) { hwr_wdb_world.access_calls++; return hwr_wdb_world.access_ok ? 0 : -1; }
static FILE *hwr_wdb_fopen(const char *path, const char *mode) { hwr_wdb_world.fopen_calls++; return hwr_wdb_world.fopen_ok ? hwr_wdb_world.file : NULL; }
static char *get_formatted_time(char *time) { hwr_wdb_world.time_calls++; strcpy(time, HWR_WDB_TS); return time; }
#define access hwr_wdb_access
#define fopen hwr_wdb_fopen
#define wifi_dpp_dbg_print hwr_sg_wifi_dpp_dbg_print

extern "C" {
/* --- wifi_hal_dpp.c:110-139 --- */
void wifi_dpp_dbg_print(char *format, ...)
{
    char buff[2048] = {0};
    va_list list;
    static FILE *fpg = NULL;

    /* ---------- start fix 1: a NULL format was passed to vsprintf. */
    if (format == NULL) {
        return;
    }
    /* ---------- end fix 1 */

    if ((access("/nvram/wifiDppDbg", R_OK)) != 0) {
        return;
    }

    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    /* ---------- start fix 2: vsprintf wrote an unbounded message into the 2048-byte stack buffer (after the time stamp), overflowing it for messages of 2025 characters or more. */
    vsnprintf(&buff[strlen(buff)], sizeof(buff) - strlen(buff), format, list);
    /* ---------- end fix 2 */
    va_end(list);

    if (fpg == NULL) {
        fpg = fopen("/tmp/wifiDPP", "a+");
        if (fpg == NULL) {
            return;
        } else {
            fputs(buff, fpg);
        }
    } else {
        fputs(buff, fpg);
    }

    fflush(fpg);
}
}

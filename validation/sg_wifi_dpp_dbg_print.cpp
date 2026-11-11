/*
 * HANDLER: wifi_dpp_dbg_print (src/wifi_hal_dpp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_dpp.c:110-139 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  When /nvram/wifiDppDbg is readable it builds
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

    if ((access("/nvram/wifiDppDbg", R_OK)) != 0) {
        return;
    }

    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
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

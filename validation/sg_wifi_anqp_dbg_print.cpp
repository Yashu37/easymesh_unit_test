/*
 * HANDLER: wifi_anqp_dbg_print (src/wifi_hal_anqp.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_anqp.c:69-103 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  When /nvram/wifiAnqpDbg is readable it builds
 * "<formatted time> <message>" in the local buff[4096] with strcat + vsprintf, opens /tmp/wifiAnqp once into a function-static FILE * and appends the text.
 *
 * Scaffolding only: access() and fopen() are the runner-controlled stubs of hwr_wdp.h (macros below), get_formatted_time is a deterministic stand-in writing HWR_WDP_TS; fputs / fflush / strcat / vsprintf
 * are the real libc functions; renamed hwr_sg_wifi_anqp_dbg_print.
 */
#include "hwr_wdp.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

hwr_wdp_world_t hwr_wdp_world;
static int hwr_wdp_access(const char *path, int mode) { hwr_wdp_world.access_calls++; return hwr_wdp_world.access_ok ? 0 : -1; }
static FILE *hwr_wdp_fopen(const char *path, const char *mode) { hwr_wdp_world.fopen_calls++; return hwr_wdp_world.fopen_ok ? hwr_wdp_world.file : NULL; }
static char *get_formatted_time(char *time) { hwr_wdp_world.time_calls++; strcpy(time, HWR_WDP_TS); return time; }
#define access hwr_wdp_access
#define fopen hwr_wdp_fopen
#define wifi_anqp_dbg_print hwr_sg_wifi_anqp_dbg_print

extern "C" {
/* --- wifi_hal_anqp.c:69-103 --- */
void wifi_anqp_dbg_print(int level, char *format, ...)
{
    char buff[4096] = {0};
    va_list list;
    static FILE *fpg = NULL;

    if ((access("/nvram/wifiAnqpDbg", R_OK)) != 0)
    {
        return;
    }
    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);
    if (fpg == NULL)
    {
        fpg = fopen("/tmp/wifiAnqp", "a+");
        if (fpg == NULL)
        {
            return;
        }
        else
        {
            fputs(buff, fpg);
        }
    }
    else
    {
        fputs(buff, fpg);
    }

    fflush(fpg);
}
}

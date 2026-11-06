/*
 * HANDLER: nvram_get_vap_enable_status
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:184 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code: it carries FIX 1 below.  The print is the real macro over the log sink.  Renamed
 * hwr_nvram_get_vap_enable_status (the other platforms define the same name).
 */
#include "hwr_nve.h"
#include <stdio.h>
#include <stdbool.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define nvram_get_vap_enable_status      hwr_nvram_get_vap_enable_status

/* --- platform.c:184 --- */
extern "C" {
int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /* FIX 1: the function returned 0 (success) without ever writing *vap_enable, so the caller read an uninitialised
     * bool as "the vap enable status".  This platform has no nvram value: report "not available" (-1), *vap_enable
     * stays untouched. */
    return -1;
}
}

/*
 * HANDLER: nvram_get_radio_enable_status
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:178 (~/Desktop/G/rdk-wifi-hal).  With RDK_NRE_FIX 0 it is the
 * VERBATIM original (reproduces the finding); with RDK_NRE_FIX 1 it carries FIX 1 below.  The print is the real macro over the log
 * sink.  Renamed hwr_nvram_get_radio_enable_status (the other platforms define the same name).
 */
#include "hwr_nre.h"
#include <stdio.h>
#include <stdbool.h>

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_NRE_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define nvram_get_radio_enable_status      hwr_nvram_get_radio_enable_status

/* --- platform.c:178 --- */
extern "C" {
#if RDK_NRE_FIX
int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /* FIX 1: the function returned 0 (success) without ever writing *radio_enable, so the caller read an uninitialised
     * bool as "the radio enable status".  This platform has no nvram value: report "not available" (-1), *radio_enable
     * stays untouched. */
    return -1;
}
#else
int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}
#endif
}

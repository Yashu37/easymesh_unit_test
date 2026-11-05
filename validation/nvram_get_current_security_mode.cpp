/*
 * HANDLER: nvram_get_current_security_mode
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:190 (~/Desktop/G/rdk-wifi-hal).  With RDK_NSM_FIX 0 it is the
 * VERBATIM original (reproduces the finding); with RDK_NSM_FIX 1 it carries FIX 1 below.  The print is the real macro over the log
 * sink.  Renamed hwr_nvram_get_current_security_mode (the other platforms define the same name).
 */
#include "hwr_nsm.h"
#include <stdio.h>
#include <stdbool.h>

/* 1 = with FIX 1, 0 = original unfixed function (set to 0 to reproduce the finding) */
#define RDK_NSM_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define nvram_get_current_security_mode      hwr_nvram_get_current_security_mode

/* --- platform.c:190 --- */
extern "C" {
#if RDK_NSM_FIX
int nvram_get_current_security_mode(wifi_security_modes_t *security_mode, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /* FIX 1: the function returned 0 (success) without ever writing *security_mode, so the caller read an uninitialised
     * enum as "the current security mode".  This platform has no nvram value: report "not available" (-1), *security_mode
     * stays untouched. */
    return -1;
}
#else
int nvram_get_current_security_mode(wifi_security_modes_t *security_mode,int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}
#endif
}

/*
 * HANDLER: platform_pre_init
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/banana-pi/platform.c:103 (~/Desktop/G/rdk-wifi-hal).  It takes no
 * argument, only logs through wifi_hal_dbg_print and returns 0; there is no fix switch because there is no finding.
 * The print is the real macro over the log sink (hwr_print).  The function is renamed hwr_platform_pre_init because the other
 * platforms define the same name.
 */
#include "hwr_ppi.h"
#include <stdio.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define platform_pre_init                  hwr_platform_pre_init

/* --- platform.c:103 --- */
extern "C" {
int platform_pre_init()
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}
}

/*
 * HANDLER: platform_flags_init
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:460 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code (the fix described in its comment).  The flag enum is the verbatim wifi_hal_platform_flags_t of
 * src/wifi_hal_priv.h (hwr_pfi.h).  The prints are the real macros over the log sink.  Renamed hwr_platform_flags_init
 * (other platforms define the same name).
 */
#include "hwr_pfi.h"
#include <stdio.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define platform_flags_init                hwr_platform_flags_init

/* --- platform.c:460 --- */
extern "C" {
int platform_flags_init(int *flags)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /* FIX: flags == NULL was written. */
    if (flags == NULL) {
        wifi_hal_error_print("%s:%d flags is NULL\n", __func__, __LINE__);
        return -1;
    }
    *flags = PLATFORM_FLAGS_STA_INACTIVITY_TIMER | PLATFORM_FLAGS_CONTROL_PORT_FRAME;
    return 0;
}
}

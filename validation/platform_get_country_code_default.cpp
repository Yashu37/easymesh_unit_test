/*
 * HANDLER: platform_get_country_code_default
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:269 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code: it carries FIX 1 below.  The prints are the real macros over the log sink.  Renamed
 * hwr_platform_get_country_code_default (other platforms define the same name).
 */
#include "hwr_pcc.h"
#include <stdio.h>
#include <string.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define platform_get_country_code_default  hwr_platform_get_country_code_default

/* --- platform.c:269 --- */
extern "C" {
int platform_get_country_code_default(char *code)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /* FIX 1: code == NULL was written by strcpy (the callers always pass a buffer, but nothing says so). */
    if (code == NULL) {
        wifi_hal_error_print("%s:%d code is NULL\n", __func__, __LINE__);
        return -1;
    }
    strcpy(code,"US");
    return 0;
}
}

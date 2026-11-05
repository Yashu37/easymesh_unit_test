/*
 * HANDLER: platform_get_wps_pin_default
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:256 (~/Desktop/G/rdk-wifi-hal).  With RDK_PWP_FIX 0 it is the
 * VERBATIM original (reproduces the findings); with RDK_PWP_FIX 1 it carries the fix described in its comment.
 * Collaborator (construct file): wifi_nvram_defaultRead is a stub with a controllable result; its copy line is the original
 * strncpy(out, position, strlen(position)+1), and -1 leaves out untouched (the function is separately harnessed).  The prints are the real
 * macros over the log sink.  Renamed hwr_platform_get_wps_pin_default (other platforms define the same name).
 */
#include "hwr_pwp.h"
#include <stdio.h>
#include <string.h>

/* 1 = with the fix, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_PWP_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_nvram_defaultRead             hwr_pwp_nvram
#define platform_get_wps_pin_default       hwr_platform_get_wps_pin_default

/* --- platform.c:256 --- */
extern "C" {
#if RDK_PWP_FIX
int platform_get_wps_pin_default(char *pin)
{
    /* FIX: (1) pin == NULL was passed to wifi_nvram_defaultRead and written.
     * (2) the result of wifi_nvram_defaultRead() was ignored and 0 returned: a missing key (pin never written) or an empty value
     *     was reported as "default WPS pin read", so the callers (wifi_dml_cb / dml_onewifi_api.c: strcpy(vap->wps_pin, pin) after
     *     RETURN_OK) used an empty pin instead of their INVALID_KEY fallback.
     * (3) a value longer than the HAL's WPS pin field (WIFI_AP_MAX_WPSPIN_LEN = 9 bytes: 8 characters + NUL) was returned as success
     *     and the callers' strcpy() into that field overflowed it.  The value is read into a local buffer and returned only when it
     *     is 1..8 characters long; pin is not touched otherwise. */
    char tmp[129] = { 0 };       /* the nvram reader writes up to 128 bytes (127 characters + NUL) */

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    if (pin == NULL) {
        wifi_hal_error_print("%s:%d pin is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (wifi_nvram_defaultRead("wps_pin", tmp) != 0 || tmp[0] == '\0' || strlen(tmp) >= WIFI_AP_MAX_WPSPIN_LEN) {
        wifi_hal_error_print("%s:%d no valid wps pin in nvram\n", __func__, __LINE__);
        return -1;
    }
    memcpy(pin, tmp, strlen(tmp) + 1);
    return 0;
}
#else
int platform_get_wps_pin_default(char *pin)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    wifi_nvram_defaultRead("wps_pin",pin);
    return 0;
}
#endif
}

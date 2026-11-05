/*
 * HANDLER: nvram_get_current_ssid
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:284 (~/Desktop/G/rdk-wifi-hal).  With RDK_NCS_FIX 0 it is the
 * VERBATIM original (reproduces the findings); with RDK_NCS_FIX 1 it carries the fix described in its comment.  The function builds the
 * default SSID "BPI_RDKB-AP<vap_index>" (or "BPI-RDKB-MLO-AP" when CONFIG_GENERIC_MLO is defined; build with -DCONFIG_GENERIC_MLO to run that
 * branch) into at most BPI_LEN_16 (16) bytes; there is no nvram access.  The prints are the real macros over the log sink.  Renamed
 * hwr_nvram_get_current_ssid (other platforms define the same name).
 */
#include "hwr_ncs.h"
#include <stdio.h>
#include <string.h>

/* 1 = with the fix, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_NCS_FIX  0

#define BPI_LEN_16 16        /* platform.c:41 */
#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define nvram_get_current_ssid             hwr_nvram_get_current_ssid

/* --- platform.c:284 --- */
extern "C" {
#if RDK_NCS_FIX
int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    /* FIX: (1) l_ssid == NULL was passed to snprintf (crash).  (2) the snprintf() result was ignored: a name that does not fit in BPI_LEN_16
     *     bytes (vap_index >= 10000 or <= -1000) was silently truncated and returned as success, so different vaps (10000..10009 -> "BPI_RDKB-AP1000")
     *     got the same SSID.  The name is built in a local buffer and copied only when it fits; otherwise -1 and l_ssid untouched. */
    char tmp[BPI_LEN_16];
    int n;

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    if (l_ssid == NULL) {
        wifi_hal_error_print("%s:%d l_ssid is NULL\n", __func__, __LINE__);
        return -1;
    }
#ifdef CONFIG_GENERIC_MLO
    n = snprintf(tmp, BPI_LEN_16, "BPI-RDKB-MLO-AP");
#else
    n = snprintf(tmp,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
#endif
    if (n < 0 || n >= BPI_LEN_16) {
        wifi_hal_error_print("%s:%d default ssid for vap %d does not fit\n", __func__, __LINE__, vap_index);
        return -1;
    }
    memcpy(l_ssid, tmp, n + 1);
    return 0;
}
#else
int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
#ifdef CONFIG_GENERIC_MLO    
    snprintf(l_ssid, BPI_LEN_16, "BPI-RDKB-MLO-AP");
#else    
    snprintf(l_ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
#endif    
    return 0;
}
#endif
}

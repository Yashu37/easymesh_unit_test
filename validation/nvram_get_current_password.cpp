/*
 * HANDLER: nvram_get_current_password
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:276 (~/Desktop/G/rdk-wifi-hal).  With RDK_NCP_FIX 0 it is the
 * VERBATIM original (reproduces the findings); with RDK_NCP_FIX 1 it carries the fix described in its comment.
 * Collaborator (construct file): wifi_nvram_defaultRead is a stub with a controllable result per call; its copy line is the original
 * strncpy(out, position, strlen(position)+1), -1 leaves out untouched.  The prints are the real macros over the log sink.  Renamed
 * hwr_nvram_get_current_password (other platforms define the same name).
 */
#include "hwr_ncp.h"
#include <stdio.h>
#include <string.h>

/* 1 = with the fix, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_NCP_FIX  0

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_nvram_defaultRead             hwr_ncp_nvram
#define nvram_get_current_password         hwr_nvram_get_current_password

/* --- platform.c:276 --- */
extern "C" {
#if RDK_NCP_FIX
int nvram_get_current_password(char *l_password, int vap_index)
{
    /* FIX: (1) the result of wifi_nvram_defaultRead() was ignored and 0 always returned: a missing key / empty value looked like
     *     "password read", so OneWifi's retry path for the private vaps (wifi_db_apis.c: if ret != 0 -> sleep(5) and ask again) never ran and
     *     bss_cfg->security.u.key.key kept whatever it held (an unwritten / empty key).  The value is read into a local buffer; 0 is returned
     *     (and l_password written) only for a non-empty password, otherwise -1 with l_password untouched.
     * (2) l_password == NULL was written. */
    char tmp[129] = { 0 };

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    if (l_password == NULL) {
        wifi_hal_error_print("%s:%d l_password is NULL\n", __func__, __LINE__);
        return -1;
    }
    /*password is not sensitive,won't grant access to real devices*/
    if (wifi_nvram_defaultRead("bpi_wifi_password",tmp) != 0 || tmp[0] == '\0') {
        wifi_hal_error_print("%s:%d no bpi_wifi_password in nvram\n", __func__, __LINE__);
        return -1;
    }
    memcpy(l_password, tmp, strlen(tmp) + 1);
    return 0;
}
#else
int nvram_get_current_password(char *l_password, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /*password is not sensitive,won't grant access to real devices*/ 
    wifi_nvram_defaultRead("bpi_wifi_password",l_password);
    return 0;
}
#endif
}

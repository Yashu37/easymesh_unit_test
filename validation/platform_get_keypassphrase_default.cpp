/*
 * HANDLER: platform_get_keypassphrase_default
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:196 (~/Desktop/G/rdk-wifi-hal).  With RDK_PGK_FIX 0 it is the
 * VERBATIM original (reproduces the findings); with RDK_PGK_FIX 1 it carries the fix described in its comment.
 * Collaborators (construct file): is_wifi_hal_vap_mesh_sta, json_parse_backhaul_keypassphrase (its copy line is the one of
 * json_parse_string: strncpy(val, str, 129); val[128] = 0, i.e. 129 bytes are ALWAYS written) and wifi_nvram_defaultRead (its copy
 * line is the original strncpy(out, position, strlen(position)+1); -1 leaves out untouched) are stubs with controllable results,
 * each of them separately harnessed.  The defines are copied from platform.c; the prints are the real macros over the log sink.
 * Renamed hwr_platform_get_keypassphrase_default (other platforms define the same name).
 */
#include "hwr_pgk.h"
#include <stdio.h>
#include <string.h>

/* 1 = with the fix, 0 = original unfixed function (set to 0 to reproduce the findings) */
#define RDK_PGK_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define MAX_KEYPASSPHRASE_LEN 129      /* platform.c:43 */
#define INVALID_KEY  "12345678"        /* platform.c:45 */
#define HWR_PGK_PW_BUF 128             /* size of the password buffers the callers pass (fix only) */
#define is_wifi_hal_vap_mesh_sta           hwr_pgk_is_mesh_sta
#define json_parse_backhaul_keypassphrase  hwr_pgk_json
#define wifi_nvram_defaultRead             hwr_pgk_nvram
#define platform_get_keypassphrase_default hwr_platform_get_keypassphrase_default

/* --- platform.c:196 --- */
extern "C" {
#if RDK_PGK_FIX
int platform_get_keypassphrase_default(char *password, int vap_index)
{
    /* FIX: (1) password == NULL was written / measured (strlen) unchecked.
     * (2) json_parse_backhaul_keypassphrase() copies with strncpy(val, str, 129): it ALWAYS writes 129 bytes (zero padded) and
     *     val[128] = 0, but the callers pass 128-byte buffers (wifi_db_apis.c, wifi_ctrl_webconfig.c, wifi_multidoc_webconfig.c) or even
     *     64 bytes (wifi_dml_cb.c): a stack overflow by >= 1 byte on every call for a mesh STA vap.  The value is now read into a
     *     local buffer and copied only when it fits the 128-byte buffer the callers use.
     * (3) the result of wifi_nvram_defaultRead() was ignored: when it failed the caller's buffer was never written and
     *     strlen(password) measured whatever the caller had in it (uninitialised stack: over-read, or stale text returned as
     *     "the default password").  The result is checked now; every failure falls back to INVALID_KEY.
     * (4) an empty value from the JSON file was returned as success (see json_parse_backhaul_keypassphrase #86). */
    char tmp[MAX_KEYPASSPHRASE_LEN] = { 0 };

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    if (password == NULL) {
        wifi_hal_error_print("%s:%d password is NULL\n", __func__, __LINE__);
        return -1;
    }
    /* if the vap_index is that of mesh STA then try to obtain the ssid from
       /nvram/EasymeshCfg.json file */
    if (is_wifi_hal_vap_mesh_sta(vap_index)) {
        if (!json_parse_backhaul_keypassphrase(tmp) && tmp[0] != '\0' && strlen(tmp) < HWR_PGK_PW_BUF) {
            memcpy(password, tmp, strlen(tmp) + 1);
            wifi_hal_dbg_print("%s:%d, read password from jSON file\n", __func__, __LINE__);
            return 0;
        }
        memset(tmp, 0, sizeof(tmp));
    }
    /*password is not sensitive,won't grant access to real devices*/
    if (wifi_nvram_defaultRead("bpi_wifi_password",tmp) == 0 && tmp[0] != '\0' && strlen(tmp) < HWR_PGK_PW_BUF) {
        memcpy(password, tmp, strlen(tmp) + 1);
        return 0;
    }
    wifi_hal_error_print("%s:%d nvram default password not found, "
                         "enforced alternative default password\n",
        __func__, __LINE__);
    strncpy(password, INVALID_KEY, strlen(INVALID_KEY) + 1);
    return 0;
}
#else
int platform_get_keypassphrase_default(char *password, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    /* if the vap_index is that of mesh STA then try to obtain the ssid from
       /nvram/EasymeshCfg.json file */
    if (is_wifi_hal_vap_mesh_sta(vap_index)) {
        if (!json_parse_backhaul_keypassphrase(password)) {
            wifi_hal_dbg_print("%s:%d, read password from jSON file\n", __func__, __LINE__);
            return 0;
        }
    }
    /*password is not sensitive,won't grant access to real devices*/ 
    wifi_nvram_defaultRead("bpi_wifi_password",password);
    if (strlen(password) == 0) {
        wifi_hal_error_print("%s:%d nvram default password not found, "
                             "enforced alternative default password\n",
            __func__, __LINE__);
        strncpy(password, INVALID_KEY, strlen(INVALID_KEY) + 1);
    }
    return 0;
}
#endif
}

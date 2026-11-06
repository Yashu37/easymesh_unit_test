/*
 * HANDLER: platform_get_ssid_default
 *
 * Function copied from rdk-wifi-hal: platform/banana-pi/platform.c:218 (~/Desktop/G/rdk-wifi-hal).  This file holds ONLY
 * THE FIXED code: it carries FIX 1..2 below. Collaborators (construct file): is_wifi_hal_vap_mesh_sta and
 * json_parse_backhaul_ssid (its copy line is the one of json_parse_string: strncpy(val, str, 33); val[32] = 0) are stubs
 * with controllable results; the serial file /nvram/serial_number.txt is a REAL file: fopen is redirected to the
 * runner's temporary file, fseek / fread / fclose are the real ones.  The defines are copied from platform.c
 * (CONFIG_GENERIC_MLO is not defined: the "BPI_RDKB-AP%d-%s" variant is tested); the prints are the real macros over the
 * log sink.  Renamed hwr_platform_get_ssid_default (other platforms define the same name).
 */
#include "hwr_psd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define BPI_LEN_32 32                  /* platform.c:40 */
#define BPI_LEN_8 8                    /* platform.c:42 */
#define fopen                              hwr_psd_fopen
#define is_wifi_hal_vap_mesh_sta           hwr_psd_is_mesh_sta
#define json_parse_backhaul_ssid           hwr_psd_json
#define platform_get_ssid_default          hwr_platform_get_ssid_default

/* --- platform.c:218 --- */
extern "C" {
int platform_get_ssid_default(char *ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n", __func__, __LINE__);
    /* FIX 1: ssid == NULL was written (JSON copy / snprintf) unchecked. */
    if (ssid == NULL) {
        wifi_hal_error_print("%s:%d ssid is NULL\n", __func__, __LINE__);
        return -1;
    }
    /* if the vap_index is that of mesh STA or mesh backhaul then try to obtain the ssid from
       /nvram/EasymeshCfg.json file */
    if (is_wifi_hal_vap_mesh_sta(vap_index)) {
        if (!json_parse_backhaul_ssid(ssid)) {
            wifi_hal_dbg_print("%s:%d, read SSID:%s from jSON file\n", __func__, __LINE__, ssid);
            return 0;
        }
    }
    char serial[BPI_LEN_8] = {0};
    FILE *fp = NULL;
    size_t bytes_read = 0;

    if((fp = fopen("/nvram/serial_number.txt", "rb")) != NULL)
    {
        if(fseek(fp, -7, SEEK_END))
        {
            wifi_hal_dbg_print("%s:%d, fseek() failed \n", __func__, __LINE__);
	        fclose(fp);
	        return -1;
        }
	    bytes_read = fread(serial, 1, sizeof(serial)-1, fp);
	    fclose(fp);
	    if(!bytes_read)
	        return -1;
	    /* FIX 2: only "\n" was cut: the last 7 bytes of a CRLF file ("...XYZ\r\n") left the "\r" in the serial and so a control
	     * character at the end of the SSID. */
	    serial[strcspn(serial, "\r\n")] = 0;
	    wifi_hal_dbg_print("%s:%d, appending serial is :%s \n", __func__, __LINE__, serial);
    }
#ifdef CONFIG_GENERIC_MLO
    snprintf(ssid, BPI_LEN_32, "BPI-RDKB-MLO-AP-%s", serial);
#else    
    snprintf(ssid, BPI_LEN_32, "BPI_RDKB-AP%d-%s", vap_index, serial);
#endif    
    return 0;
}
}

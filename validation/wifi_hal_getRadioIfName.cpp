/*
 * HANDLER: wifi_hal_getRadioIfName
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:605-625
 * (~/Desktop/G/rdk-wifi-hal), with the struct ovs_radioname_cloudradioname_map (593-597) and the table
 * cloud_radio_map (599-602) copied verbatim next to it (the table is declared static here only so the
 * harnesses link together).  This file holds ONLY THE FIXED function (the bounds check on radioIndex described
 * in the comment below); the original unfixed version is not in this file.
 *
 * Scaffolding only: g_wifi_hal holds just num_radios (the runner sets it per case); the prints are the real macros
 * over the log sink.  The function under test is renamed hwr_wifi_hal_getRadioIfName (ipc_server_output
 * already stubs the real name).
 */
#include "hwr_gri.h"
#include <string.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal            hwr_gri_world
#define wifi_hal_getRadioIfName hwr_wifi_hal_getRadioIfName
#define ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

hwr_gri_world_t hwr_gri_world;

/* --- copied from hal_ipc_wifi_wrappers.c:593 --- */
struct ovs_radioname_cloudradioname_map {
    unsigned int radio_index;
    char cloudradioname[64];
    char gw_radio_name[64];
};

static struct ovs_radioname_cloudradioname_map cloud_radio_map[] = {
    {0, "wl0", "wlan0"},
    {1, "wl1", "wlan2"}
};

/* --- copied from hal_ipc_wifi_wrappers.c:605 --- */
extern "C" {
INT wifi_hal_getRadioIfName(INT radioIndex, CHAR *output_string)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    /* FIX 1: the index was compared with `>` against the number of radios only: an index equal to num_radios
     * passed, and cloud_radio_map has just two entries, so an index of 2 (radio 3 of 3, or index == num_radios)
     * read cloud_radio_map[2] out of bounds (log line and strcpy).  Require 0 <= index < num_radios and
     * index < the size of the table. */
    if (radioIndex < 0 || (unsigned int)radioIndex >= g_wifi_hal.num_radios ||
        (unsigned int)radioIndex >= ARRAY_SZ(cloud_radio_map)){
        wifi_hal_dbg_print("%s:%d: radio index %d out of range.\n", __func__, __LINE__, radioIndex);
        return -1;
    }

    if (!output_string){
        wifi_hal_error_print("%s:%d: NULL pointer string passed.\n", __func__, __LINE__);
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Requested radio index %d GW name %s translated to cloud name %s .\n", __func__, __LINE__,
                                radioIndex, cloud_radio_map[radioIndex].gw_radio_name, cloud_radio_map[radioIndex].cloudradioname);

    strcpy(output_string, cloud_radio_map[radioIndex].cloudradioname);

    return 0;
}
}

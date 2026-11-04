/*
 * HANDLER: wifi_hal_getApName
 *
 * Function copied from rdk-wifi-hal: hal_ipc/server/hal_ipc_wifi_wrappers.c:169-186
 * (~/Desktop/G/rdk-wifi-hal), together with the three helpers it depends on, copied from
 * src/wifi_hal_nl80211_utils.c (the non-FEATURE_SINGLE_PHY build): get_total_num_of_vaps (:4926),
 * get_interface_name_from_vap_index (:2235) and get_radio_by_rdk_index (:2271); they are declared static
 * here only so the harnesses link together.  With RDK_GAN_FIX 0 everything is the VERBATIM original (reproduces
 * the findings); with RDK_GAN_FIX 1 the two helpers carry FIX 1 below.
 *
 * Scaffolding only: g_wifi_hal / radio hold just num_radios, radio_info[], rdk_radio_index and
 * capab.maxNumberVAPs; interface_index_map is a runner-owned array of the REAL wifi_interface_name_idex_map_t
 * (wifi_hal.h); get_sizeof_interfaces_index_map returns its size.  The function under test is renamed
 * hwr_wifi_hal_getApName (ipc_server_output already stubs the real name).
 */
#include "hwr_gan.h"
#include <string.h>

/* 1 = with FIX 1 in the helpers, 0 = original unfixed code (set to 0 to reproduce the findings) */
#define RDK_GAN_FIX  1

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_radio_info_t     hwr_gan_radio_t
#define g_wifi_hal            hwr_gan_world
#define interface_index_map   hwr_gan_map
#define wifi_hal_getApName    hwr_wifi_hal_getApName

hwr_gan_world_t hwr_gan_world;
wifi_interface_name_idex_map_t hwr_gan_map[HWR_GAN_MAP_MAX];
unsigned int hwr_gan_map_size;

static unsigned int get_sizeof_interfaces_index_map(void) { return hwr_gan_map_size; }

/* --- copied from wifi_hal_nl80211_utils.c:2271 --- */
static wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    unsigned int i;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];
        if (radio->rdk_radio_index == index) {
            return radio;
        }
    }
    return NULL;
}

/* --- copied from wifi_hal_nl80211_utils.c:4926 (FIX 1 inside) --- */
static int get_total_num_of_vaps(void)
{
    unsigned char l_index = 0;
    int total_num_of_vaps = 0;
    wifi_radio_info_t *radio;

    for (l_index = 0; l_index < g_wifi_hal.num_radios; l_index++) {
#ifndef FEATURE_SINGLE_PHY
#if RDK_GAN_FIX
        /* FIX 1: the radio_info[] position is the loop index, not an rdk radio index.  Looking it up by rdk
         * index returned NULL for radios whose rdk index differs from their position and radio->capab was then
         * dereferenced (the FEATURE_SINGLE_PHY branch below already indexes the array directly). */
        radio = &g_wifi_hal.radio_info[l_index];
#else
        radio = get_radio_by_rdk_index(l_index);
#endif
#else //FEATURE_SINGLE_PHY
        radio = &g_wifi_hal.radio_info[l_index];
#endif //FEATURE_SINGLE_PHY
        total_num_of_vaps += radio->capab.maxNumberVAPs;
    }

    return total_num_of_vaps;
}

/* --- copied from wifi_hal_nl80211_utils.c:2235 (FIX 1 inside) --- */
static int get_interface_name_from_vap_index(unsigned int vap_index, char *interface_name)
{
    // OneWifi interafce mapping with vap_index
    unsigned char l_index = 0;
    unsigned char total_num_of_vaps = 0;
    const char *l_interface_name = NULL;
    wifi_radio_info_t *radio;

    for (l_index = 0; l_index < g_wifi_hal.num_radios; l_index++) {
#ifndef FEATURE_SINGLE_PHY
#if RDK_GAN_FIX
        /* FIX 1: the radio_info[] position is the loop index, not an rdk radio index.  Looking it up by rdk
         * index returned NULL for radios whose rdk index differs from their position and radio->capab was then
         * dereferenced (the FEATURE_SINGLE_PHY branch below already indexes the array directly). */
        radio = &g_wifi_hal.radio_info[l_index];
#else
        radio = get_radio_by_rdk_index(l_index);
#endif
#else //FEATURE_SINGLE_PHY
        radio = &g_wifi_hal.radio_info[l_index];
#endif //FEATURE_SINGLE_PHY
        total_num_of_vaps += radio->capab.maxNumberVAPs;
    }

    if ((vap_index >= total_num_of_vaps) || (interface_name == NULL)) {
        wifi_hal_error_print("%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    for (l_index = 0; l_index < get_sizeof_interfaces_index_map(); l_index++) {
        if (interface_index_map[l_index].index == vap_index) {
            l_interface_name = interface_index_map[l_index].interface_name;
            strncpy(interface_name, l_interface_name, (strlen(l_interface_name) + 1));
            wifi_hal_dbg_print("%s:%d: VAP index %d: interface name %s\n", __func__, __LINE__, vap_index, interface_name);
            return RETURN_OK;
        }
    }

    wifi_hal_error_print("%s:%d: Interface name not found:%d \n",__func__, __LINE__, vap_index);

    return RETURN_ERR;
}

/* --- copied from hal_ipc_wifi_wrappers.c:169 --- */
extern "C" {
INT wifi_hal_getApName( INT apIndex,
                        CHAR *output_string)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    if (apIndex >= get_total_num_of_vaps()) {
        wifi_hal_dbg_print("%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    if(get_interface_name_from_vap_index(apIndex, output_string) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:Failed to get ap name for ap index:%d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: Requested index %d cloud name is %s.\n", __func__, __LINE__, apIndex, output_string);

    return RETURN_OK;
}
}

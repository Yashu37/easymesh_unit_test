/*
 * HANDLER: wifi_hal_getInterfaceMap (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:116-127 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * It asks get_sizeof_interfaces_index_map() for the number of entries, rejects the call when max_entries is smaller, otherwise get_wifi_interface_info_map()
 * copies that many entries into if_map.  if_map and if_map_size are never checked: if_map_size NULL is dereferenced at once, if_map NULL is passed to memcpy.
 *
 * Scaffolding only: get_sizeof_interfaces_index_map / get_wifi_interface_info_map (src/wifi_hal_nl80211_utils.c:1574 / 2054, non-emulator build) are stubs with the
 * same behaviour over a runner-owned table (size, then memcpy(size * 176 bytes)); the print macro maps to the log sink hwr_print.  Renamed
 * hwr_sg_wifi_hal_getInterfaceMap.
 */
#include "hwr_gim.h"
#include <string.h>

#define wifi_hal_error_print(format, ...)  hwr_print(0, format, ##__VA_ARGS__)
#define wifi_interface_name_idex_map_t hwr_gim_entry_t
#define INT int
#define RETURN_OK 0
#define RETURN_ERR -1
#define wifi_hal_getInterfaceMap hwr_sg_wifi_hal_getInterfaceMap

hwr_gim_world_t hwr_gim_world;

extern "C" {
unsigned int get_sizeof_interfaces_index_map(void) { hwr_gim_world.size_calls++; return hwr_gim_world.size; }
void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map)
{
    hwr_gim_world.map_calls++;
    memcpy(interface_map, hwr_gim_world.table, get_sizeof_interfaces_index_map()*sizeof(wifi_interface_name_idex_map_t));
}

/* --- wifi_hal.c:116-127 --- */
INT wifi_hal_getInterfaceMap(wifi_interface_name_idex_map_t *if_map, unsigned int max_entries,
    unsigned int *if_map_size)
{
    *if_map_size = get_sizeof_interfaces_index_map();
    if (max_entries < *if_map_size) {
        wifi_hal_error_print("%s:%d: Invalid buffer size %d, expected %d\n", __func__, __LINE__,
            max_entries, *if_map_size);
        return RETURN_ERR;
    }
    get_wifi_interface_info_map(if_map);
    return RETURN_OK;
}
}

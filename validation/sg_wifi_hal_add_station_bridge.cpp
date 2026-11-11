/*
 * HANDLER: wifi_hal_add_station_bridge (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4968-4977 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It removes the interface from any bridge
 * (nl80211_remove_from_bridge, result ignored) and then puts it on the given bridge (nl80211_create_bridge); a non-zero result of the latter -> RETURN_ERR, otherwise 0.
 *
 * Scaffolding only: the two nl80211 helpers are recording stubs that dereference their name arguments like the real ones (see hwr_wsb.h); the print macro goes to the log sink hwr_print; renamed
 * hwr_sg_wifi_hal_add_station_bridge.
 */
#include "hwr_wsb.h"
#include <stdio.h>
#include <string.h>

hwr_wsb_world_t hwr_wsb_world;
#define wifi_hal_error_print(format, ...) hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_add_station_bridge hwr_sg_wifi_hal_add_station_bridge
static int nl80211_remove_from_bridge(const char *if_name)
{
	hwr_wsb_world_t *w = &hwr_wsb_world;
	w->seen_len = strlen(if_name);           /* the real one hands if_name to rtnl_link_get_by_name / ovs_if_get_br: NULL crashes there */
	w->rm_calls++; w->rm_order = ++w->order; w->rm_name = if_name;
	return w->rm_ret;
}
static int nl80211_create_bridge(const char *if_name, const char *br_name)
{
	hwr_wsb_world_t *w = &hwr_wsb_world;
	w->seen_len = strlen(if_name) + strlen(br_name);   /* is_wifi_hal_vap_hotspot_from_interfacename(if_name), rtnl_link_bridge_add(sk, br_name), ... */
	w->cr_calls++; w->cr_order = ++w->order; w->cr_if = if_name; w->cr_br = br_name;
	return w->cr_ret;
}

/* --- wifi_hal.c:4968-4977 --- */
int wifi_hal_add_station_bridge( char *interface_name,char *bridge_name)
{
    nl80211_remove_from_bridge(interface_name);
    if (nl80211_create_bridge(interface_name, bridge_name) != 0) {
        wifi_hal_error_print("%s:%d: Interface:%s failed to create bridge:%s\n",
            __func__, __LINE__, interface_name, bridge_name);
        return RETURN_ERR;
    }
    return 0;
}

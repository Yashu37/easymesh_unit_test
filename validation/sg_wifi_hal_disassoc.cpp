/*
 * HANDLER: wifi_hal_disassoc (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:4824-4844 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It looks the interface up by vap index, copies the AP's own address
 * (interface->u.ap.hapd.own_addr) under g_wifi_hal.hapd_lock and asks the driver to disassociate the station mac with the given status (reason).
 *
 * Scaffolding only: get_interface_by_vap_index is a lookup over the runner's interfaces (NULL for an unknown vap index); wifi_drv_sta_disassoc is a recording stub with the non-BANANA_PI_PORT signature
 * (the 4-argument branch of the #if below is the one compiled); g_wifi_hal is a stand-in holding only hapd_lock; renamed hwr_sg_wifi_hal_disassoc.
 */
#include "hwr_wdi.h"
#include <stdio.h>
#include <string.h>

hwr_wdi_world_t hwr_wdi_world;
#define g_wifi_hal hwr_wdi_world.hal
#define wifi_hal_disassoc hwr_sg_wifi_hal_disassoc
#define wifi_hal_error_print(format, ...) hwr_print(1, format, ##__VA_ARGS__)
static wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
	for (int i = 0; i < HWR_WDI_MAXI; i++) if ((unsigned int)hwr_wdi_world.vap_ids[i] == vap_index) return &hwr_wdi_world.ifs[i];
	return NULL;
}
static int wifi_drv_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
{
	hwr_wdi_world_t *w = &hwr_wdi_world;
	w->calls++; w->call_priv = priv; memcpy(w->call_own, own_addr, ETH_ALEN); w->call_addr = addr; w->call_reason = reason;
	w->lock_free_in_call = (pthread_mutex_trylock(&w->hal.hapd_lock) == 0);
	if (w->lock_free_in_call) pthread_mutex_unlock(&w->hal.hapd_lock);
	return 0;
}

extern "C" {
/* --- wifi_hal.c:4824-4844 --- */
void wifi_hal_disassoc(int vap_index, int status, uint8_t *mac)
{
    u8 own_addr[ETH_ALEN];
    wifi_interface_info_t *interface = get_interface_by_vap_index(vap_index);
    /* ---------- start fix 1: get_interface_by_vap_index returns NULL for an unknown vap index; interface->u.ap.hapd.own_addr was read through it. */
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface for vap index:%d not found\n", __func__, __LINE__, vap_index);
        return;
    }
    /* ---------- end fix 1 */
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    memcpy(own_addr, hapd->own_addr, ETH_ALEN);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
#if HOSTAPD_VERSION >= 211 && defined(CONFIG_GENERIC_MLO)
    int link_id = wifi_hal_get_mld_link_id(interface);
#else
    int link_id = NL80211_DRV_LINK_ID_NA;
#endif // HOSTAPD_VERSION >= 211 && CONFIG_GENERIC_MLO
    wifi_drv_sta_disassoc(interface, own_addr, mac, status, link_id);
#else
    wifi_drv_sta_disassoc(interface, own_addr, mac, status);
#endif // BANANA_PI_PORT && KERNEL_6_6
}
}

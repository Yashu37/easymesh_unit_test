/*
 * HANDLER: wifi_hal_delHostapdDenyAclDevice (src/wifi_hal.c)
 *
 * Function copied from rdk-wifi-hal (verbatim apart from fix 1): src/wifi_hal.c:2026-2056 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code with fix 1 applied (start fix 1 / end fix 1 markers; the unfixed copy is the reproducer).  It looks the interface up by vap index, requires an AP VAP and
 * a non-NULL MAC string, takes g_wifi_hal.hapd_lock, requires hapd->conf, removes the MAC from hapd->conf->deny_mac (hostapd_ctrl_iface_acl_del_mac) and then calls hostapd_set_acl(hapd)
 * (hapd->iface is not checked) before unlocking.
 *
 * Scaffolding only: get_interface_by_vap_index / hostapd_ctrl_iface_acl_del_mac / hostapd_set_acl are stubs over the runner's world; g_wifi_hal is the stand-in
 * hwr_wdd_world.hal; the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_delHostapdDenyAclDevice.
 */
#include "hwr_wdd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)          hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)         hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define g_wifi_hal hwr_wdd_world.hal
#define get_interface_by_vap_index hwr_wdd_get_interface_by_vap_index
#define hostapd_ctrl_iface_acl_del_mac hwr_wdd_acl_del_mac
#define hostapd_set_acl hwr_wdd_hostapd_set_acl
#define wifi_hal_delHostapdDenyAclDevice hwr_sg_wifi_hal_delHostapdDenyAclDevice

hwr_wdd_world_t hwr_wdd_world;

static int hexv(int c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
/* hostapd hwaddr_aton: six hex pairs separated by ':'; reads a character only after the previous ones were accepted */
static int hwaddr_aton(const char *txt, unsigned char *addr)
{
    for (int i = 0; i < 6; i++) {
        int a = hexv((unsigned char)txt[0]); if (a < 0) return -1;
        int b = hexv((unsigned char)txt[1]); if (b < 0) return -1;
        addr[i] = (unsigned char)((a << 4) | b);
        if (i < 5) { if (txt[2] != ':') return -1; txt += 3; }
    }
    return 0;
}

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (int k = 0; k < hwr_wdd_world.n_if; k++)
        if (hwr_wdd_world.ifs[k].vap_info.vap_index == vap_index) return &hwr_wdd_world.ifs[k];
    return NULL;
}
int hostapd_ctrl_iface_acl_del_mac(struct mac_acl_entry **acl, int *num, const char *txtaddr)
{
    unsigned char addr[6];
    hwr_wdd_world.del_calls++;
    if (!(*num)) return 0;                                      /* as hostapd: nothing to remove, the MAC is not even parsed */
    if (hwaddr_aton(txtaddr, addr)) return -1;
    for (int i = 0; i < *num; i++) if (memcmp((*acl)[i].addr, addr, 6) == 0) {
        memmove(&(*acl)[i], &(*acl)[i + 1], (*num - i - 1) * sizeof(**acl));
        (*num)--;
        break;
    }
    return 0;
}
int hostapd_set_acl(struct hostapd_data *hapd)
{
    hwr_wdd_world.set_acl_calls++;
    if (hapd->iface->drv_max_acl_mac_addrs == 0) return 0;     /* the real one reads hapd->iface first */
    return 0;
}

/* --- wifi_hal.c:2058-2087 --- */
INT wifi_hal_delHostapdDenyAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;

    interface = get_interface_by_vap_index(apIndex);

    if ((!interface) || (interface->vap_info.vap_mode != wifi_vap_mode_ap)  || (DeviceMacAddress == NULL))
        return RETURN_ERR;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (!hapd->conf) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: CACR: Removing STAs from hostapd ACL list\n", __func__, __LINE__);
    if (hostapd_ctrl_iface_acl_del_mac(&hapd->conf->deny_mac, &hapd->conf->num_deny_mac, DeviceMacAddress)) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_ERR;
    }

    hostapd_set_acl(hapd);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    return RETURN_OK;
}
}

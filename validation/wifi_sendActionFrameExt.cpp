/*
 * HANDLER: wifi_sendActionFrameExt
 *
 * Functions copied VERBATIM from rdk-wifi-hal (~/Desktop/G/rdk-wifi-hal): the banana-pi forwarder wifi_sendActionFrameExt
 * (platform/banana-pi/platform.c:660-664), which calls wifi_hal_send_mgmt_frame (src/wifi_hal.c:4775-4822, HOSTAPD_2_10 branch) where the logic is.
 * This file holds ONLY THE FIXED code: it carries FIX 1 (marked start fix / end fix) in wifi_hal_send_mgmt_frame.
 *
 * Scaffolding only (the real types need the hostap / driver header tree, see hwr_sae.h):
 *  - reduced struct ieee80211_hdr / ieee80211_mgmt (the 24-byte header and the action category byte), IEEE80211_FC and the frame control constants.
 *  - get_interface_by_vap_index: runner-controlled lookup.  os_zalloc / os_free / os_memcpy over calloc / free / memcpy (os_zalloc can be made to fail).
 *  - wifi_drv_send_mlme (src/wifi_hal_nl80211.c:13856): a recording stub.  It records the arguments and a copy of the frame and reads
 *    mgmt->u.action.category of the frame exactly as the real function does for an action frame (wifi_hal_nl80211.c:13954-13957); nl80211 is a
 *    netlink call.  Its return value is set by the runner.
 *  - the print macros are mapped to the log sink hwr_print (runner-poisoned slot).
 */
#include "hwr_sae.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_dbg_print(format, ...)    hwr_print(0, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  hwr_print(1, format, ##__VA_ARGS__)
#define wifi_hal_send_mgmt_frame  hwr_wifi_hal_send_mgmt_frame
#define wifi_sendActionFrameExt   hwr_wifi_sendActionFrameExt
#define HOSTAPD_2_10 1
#define ETH_ALEN 6
#define wifi_interface_info_t  sae_interface_t
#define os_memcpy memcpy
typedef unsigned char u8;
typedef unsigned short u16;
#define WLAN_FC_TYPE_MGMT     0
#define WLAN_FC_STYPE_ACTION  13
#define IEEE80211_FC(type, stype) ((u16)(((type) << 2) | ((stype) << 4)))

sae_world_t hwr_sae_world;

static sae_interface_t *get_interface_by_vap_index(unsigned int vap_index)
{
    return (hwr_sae_world.iface && hwr_sae_world.iface->vap_index == vap_index) ? hwr_sae_world.iface : NULL;
}
static void *os_zalloc(size_t size) { return hwr_sae_world.fail_alloc ? NULL : calloc(1, size); }
static void os_free(void *p) { free(p); }

/* --- stub of wifi_drv_send_mlme (HOSTAPD_2_10 signature) --- */
static int wifi_drv_send_mlme(void *priv, const u8 *data, size_t data_len, int noack, unsigned int freq, const u16 *csa_offs,
                              size_t csa_offs_len, int no_encrypt, unsigned int wait)
{
    sae_mgmt_t *mgmt = (sae_mgmt_t *)data;
    sae_world_t *w = &hwr_sae_world;
    (void)priv;
    w->mlme_calls++; w->mlme_len = data_len; w->mlme_noack = noack; w->mlme_freq = freq; w->mlme_wait = wait;
    w->mlme_csa = (csa_offs != NULL) || csa_offs_len != 0; w->mlme_no_encrypt = no_encrypt;
    /* wifi_hal_nl80211.c:13954: the ACTION case of the frame log reads mgmt->u.action.category */
    w->mlme_cat = mgmt->u.action.category;
    memcpy(w->mlme_frame, data, data_len < SAE_FRAME_MAX ? data_len : SAE_FRAME_MAX);
    return w->mlme_rc;
}

/* --- src/wifi_hal.c:4775 --- */
extern "C" {
int wifi_hal_send_mgmt_frame(int apIndex,mac_address_t sta, const unsigned char *data,size_t data_len,unsigned int freq, unsigned int wait)
{

    wifi_hal_dbg_print("%s:%d:Enter interface for ap index:%d\n", __func__, __LINE__, apIndex);
    wifi_interface_info_t *interface;
    u8 *buf;
    struct ieee80211_hdr *hdr;
    mac_address_t bssid_buf;
    int res = 0;
#ifdef HOSTAPD_2_11 // 2.11
    int link_id = 0;
#endif
    memset(bssid_buf, 0xff, sizeof(bssid_buf));

    /* ---------- start fix 1: frame == NULL with len > 0 and MacAddr == NULL were copied (SEGV), and len == 0 built a 24-byte buffer
     * of which wifi_drv_send_mlme reads byte 24 (mgmt->u.action.category) - an action frame needs at least the category byte. */
    if (sta == NULL || data == NULL || data_len == 0) {
        wifi_hal_error_print("%s:%d: invalid parameters (sta:%p data:%p len:%zu)\n", __func__, __LINE__, (const void *)sta, (const void *)data, data_len);
        return -1;
    }
    /* ---------- end fix 1 */

    buf = os_zalloc(24 + data_len);
    if (buf == NULL)
        return -1;
    os_memcpy(buf + 24, data, data_len);
    hdr = (struct ieee80211_hdr *) buf;
    hdr->frame_control =
        IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);

    if ((interface = get_interface_by_vap_index(apIndex)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        os_free(buf);
        return -1;
    }
    os_memcpy(hdr->addr1, sta, ETH_ALEN);
    os_memcpy(hdr->addr2, interface->mac, ETH_ALEN);
    os_memcpy(hdr->addr3, bssid_buf, ETH_ALEN);

    
#ifdef HOSTAPD_2_11 // 2.11
    // Action frames will get rejected by kernel if we pass a valid link_id for non-MLO case.
    if(!wifi_hal_is_mld_enabled(interface)) {
        link_id = -1;
    }
    res = wifi_drv_send_mlme(interface, buf, 24 + data_len, 1, freq, NULL, 0, 0, wait, link_id);
#elif HOSTAPD_2_10 // 2.10
    res = wifi_drv_send_mlme(interface, buf, 24 + data_len, 1, freq, NULL, 0, 0, wait);
#else
    res = wifi_drv_send_mlme(interface, buf, 24 + data_len, 1, freq, NULL, 0);
#endif

    os_free(buf);
    wifi_hal_dbg_print("%s:%d:Exit for mgmt frame on AP (%d), IF (%d)\n", __func__, __LINE__, apIndex, interface->index);
    return res;
}
}

/* --- platform.c:660 --- */
extern "C" {
INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    int res = wifi_hal_send_mgmt_frame(apIndex, MacAddr, frame, len, frequency, wait);
    return (res == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_ERROR;
}
}

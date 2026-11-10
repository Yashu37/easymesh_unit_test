/*
 * HANDLER: wifi_hal_sm_deinit (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:1131-1153 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It looks the interface up by vap_index, refuses
 * a VAP that is not a STA VAP and, when the STA VAP has a wpa_sm, deinitialises its eapol state machine, clears the eapol pointer, deinitialises the wpa_sm and clears the pointer.
 *
 * Scaffolding only: get_interface_by_vap_index (the real search over the interfaces) is a stub over the runner's interfaces; eapol_sm_deinit / wpa_sm_deinit free the runner-allocated objects
 * and record the call (a NULL eapol is tolerated, as in hostap); the *_print macros go to the log sink hwr_print.  Renamed hwr_sg_wifi_hal_sm_deinit.
 */
#include "hwr_wsd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define wifi_hal_error_print(format, ...)        hwr_print(1, format, ##__VA_ARGS__)
#define get_interface_by_vap_index hwr_wsd_get_interface_by_vap_index
#define eapol_sm_deinit hwr_wsd_eapol_sm_deinit
#define wpa_sm_deinit hwr_wsd_wpa_sm_deinit
#define wifi_hal_sm_deinit hwr_sg_wifi_hal_sm_deinit

hwr_wsd_world_t hwr_wsd_world;

extern "C" {
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index)
{
    for (unsigned int i = 0; i < hwr_wsd_world.num_ifs; i++)
        if (hwr_wsd_world.ifs[i].vap_info.vap_index == vap_index) return &hwr_wsd_world.ifs[i];
    return NULL;
}
void eapol_sm_deinit(struct eapol_sm *sm) { hwr_wsd_world.eapol_calls++; hwr_wsd_world.eapol_arg = sm; free(sm); }
void wpa_sm_deinit(struct wpa_sm *sm) { hwr_wsd_world.sm_calls++; hwr_wsd_world.sm_arg = sm; hwr_wsd_world.sm_eapol_at_call = sm; free(sm); }

/* --- wifi_hal.c:1131-1153 --- */
INT wifi_hal_sm_deinit(INT vap_index)
{
    wifi_interface_info_t *interface = get_interface_by_vap_index(vap_index);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface for vap index:%d not found\n", __func__, __LINE__,
            vap_index);
        return RETURN_ERR;
    }

    if (interface->vap_info.vap_mode != wifi_vap_mode_sta) {
        wifi_hal_error_print("%s:%d:interface for vap index:%d not found\n", __func__, __LINE__,
            vap_index);
        return RETURN_ERR;
    }

    if (interface->u.sta.wpa_sm != NULL) {
        eapol_sm_deinit(interface->u.sta.wpa_sm->eapol);
        interface->u.sta.wpa_sm->eapol = NULL;
        wpa_sm_deinit(interface->u.sta.wpa_sm);
        interface->u.sta.wpa_sm = NULL;
    }
    return RETURN_OK;
}
}

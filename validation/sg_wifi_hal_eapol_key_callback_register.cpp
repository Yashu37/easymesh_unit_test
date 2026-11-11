/*
 * HANDLER: wifi_hal_eapol_key_callback_register (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:4531-4543 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It appends the callback to
 * callbacks->eapol_key_cb[num_eapol_key_cbs] and increments num_eapol_key_cbs, unless the callbacks table is not available or num_eapol_key_cbs >= MAX_REGISTERED_CB_NUM (4),
 * in which case it returns silently.
 *
 * Scaffolding only: get_hal_device_callbacks is an accessor over the runner's stand-alone table (the real one, wifi_hal.c:4764, returns the address of g_wifi_hal.callbacks); MAX_REGISTERED_CB_NUM is 4
 * (action_framework.h:59); renamed hwr_sg_wifi_hal_eapol_key_callback_register.
 */
#include "hwr_wek.h"
#include <stdio.h>
#include <string.h>

wifi_device_callbacks_t hwr_wek_table;
int hwr_wek_no_table;
INT hwr_wek_cb_a(int apIndex, char *mac, eapol_msg_type_t msg_type, unsigned long long replay_counter) { return 1; }
INT hwr_wek_cb_b(int apIndex, char *mac, eapol_msg_type_t msg_type, unsigned long long replay_counter) { return 2; }
#define get_hal_device_callbacks hwr_wek_get_hal_device_callbacks
#define wifi_hal_eapol_key_callback_register hwr_sg_wifi_hal_eapol_key_callback_register

extern "C" {
wifi_device_callbacks_t *get_hal_device_callbacks() { return hwr_wek_no_table ? NULL : &hwr_wek_table; }

/* --- wifi_hal.c:4531-4543 --- */
void wifi_hal_eapol_key_callback_register(wifi_eapol_key_callback func)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL || callbacks->num_eapol_key_cbs >= MAX_REGISTERED_CB_NUM) {
        return;
    }

    callbacks->eapol_key_cb[callbacks->num_eapol_key_cbs] = func;
    callbacks->num_eapol_key_cbs++;
}
}

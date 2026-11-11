/*
 * HANDLER: wifi_8021x_data_tx_callback_register (src/wifi_hal_data_rx.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_data_rx.c:94-101 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback (NULL included, which
 * clears it) in the EAPOL frame tx slot of the device callbacks table returned by get_device_callbacks().
 *
 * Scaffolding only: get_device_callbacks is an accessor over the runner's table (the real one, wifi_hal_rdk_util.c:68, returns &g_device_callbacks and never NULL); renamed
 * hwr_sg_wifi_8021x_data_tx_callback_register.
 */
#include "hwr_wtx.h"
#include <string.h>

hwr_wtx_world_t hwr_wtx_world;
void hwr_wtx_tx_a(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len) { }
void hwr_wtx_tx_b(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len) { }
void hwr_wtx_rx_a(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len) { }
#define get_device_callbacks hwr_wtx_get_device_callbacks
#define wifi_8021x_data_tx_callback_register hwr_sg_wifi_8021x_data_tx_callback_register

extern "C" {
wifi_device_callbacks_t *get_device_callbacks()
{
    hwr_wtx_world.accessor_calls++;
    return &hwr_wtx_world.cbs;
}

/* --- wifi_hal_data_rx.c:94-101 --- */
void wifi_8021x_data_tx_callback_register(wifi_sent8021xFrame_callback func)
{
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();

       callbacks->eapol_frame_tx_callback = func;
}
}

/*
 * HANDLER: wifi_8021x_data_rx_callback_register (src/wifi_hal_data_rx.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal_data_rx.c:103-110 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code (no fixes).  It stores the callback (NULL included, which
 * clears it) in the EAPOL frame rx slot of the device callbacks table returned by get_device_callbacks().
 *
 * Scaffolding only: get_device_callbacks is an accessor over the runner's table (the real one, wifi_hal_rdk_util.c:68, returns &g_device_callbacks and never NULL); renamed
 * hwr_sg_wifi_8021x_data_rx_callback_register.
 */
#include "hwr_wrx.h"
#include <string.h>

hwr_wrx_world_t hwr_wrx_world;
void hwr_wrx_rx_a(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len) { }
void hwr_wrx_rx_b(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len) { }
void hwr_wrx_tx_a(unsigned int ap_index, mac_address_t sta, wifi_eapol_type_t type, void *data, unsigned int len) { }
#define get_device_callbacks hwr_wrx_get_device_callbacks
#define wifi_8021x_data_rx_callback_register hwr_sg_wifi_8021x_data_rx_callback_register

extern "C" {
wifi_device_callbacks_t *get_device_callbacks()
{
    hwr_wrx_world.accessor_calls++;
    return &hwr_wrx_world.cbs;
}

/* --- wifi_hal_data_rx.c:103-110 --- */
void wifi_8021x_data_rx_callback_register(wifi_received8021xFrame_callback func)
{
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();

       callbacks->eapol_frame_rx_callback = func;
}
}

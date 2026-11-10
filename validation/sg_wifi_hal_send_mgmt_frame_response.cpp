/*
 * HANDLER: wifi_hal_send_mgmt_frame_response (src/wifi_hal.c)
 *
 * Function copied VERBATIM from rdk-wifi-hal: src/wifi_hal.c:691-703 (~/Desktop/G/rdk-wifi-hal).  This file holds the ORIGINAL code: no fix is applied.
 * status OK (0) hands (ap_index, frame, len) to wifi_send_wpa_supplicant_event(); status DENY (1) hands (ap_index, mac, type, status_code, rssi) to
 * wifi_send_response_failure(); any other status logs "Undefined status" and returns RETURN_ERR.  Both successful paths return RETURN_OK regardless of what the callee did (they
 * return nothing / an ignored int).  frame, mac and len are only forwarded: the wrapper never dereferences them and never relates len to the frame (the callees' own entries are later
 * in the list; wifi_send_wpa_supplicant_event also dereferences a NULL interface for an unknown ap_index, tested there).
 *
 * Scaffolding only: wifi_send_wpa_supplicant_event / wifi_send_response_failure (src/wifi_hal_nl80211.c:14107 / 14053) are stubs that count the call and record their arguments; the
 * print macro maps to hwr_print.  Renamed hwr_sg_wifi_hal_send_mgmt_frame_response.
 */
#include "hwr_wmr.h"

#define wifi_hal_error_print(format, ...)  hwr_print(0, format, ##__VA_ARGS__)
#define INT int
#define RETURN_OK 0
#define RETURN_ERR -1
#define MGMT_FRAME_RESPONSE_STATUS_OK 0
#define MGMT_FRAME_RESPONSE_STATUS_DENY 1
#define wifi_send_wpa_supplicant_event hwr_wmr_send_wpa_supplicant_event
#define wifi_send_response_failure hwr_wmr_send_response_failure
#define wifi_hal_send_mgmt_frame_response hwr_sg_wifi_hal_send_mgmt_frame_response

hwr_wmr_world_t hwr_wmr_world;

extern "C" {
void wifi_send_wpa_supplicant_event(int ap_index, uint8_t *frame, int len)
{
    hwr_wmr_world.ok_calls++; hwr_wmr_world.ap = ap_index; hwr_wmr_world.frame = frame; hwr_wmr_world.len = len;
}
int wifi_send_response_failure(int ap_index, const uint8_t *mac, int frame_type, int status_code, int rssi)
{
    hwr_wmr_world.deny_calls++; hwr_wmr_world.fap = ap_index; hwr_wmr_world.mac = mac; hwr_wmr_world.type = frame_type; hwr_wmr_world.status_code = status_code; hwr_wmr_world.rssi = rssi;
    return 0;
}

/* --- wifi_hal.c:691-703 --- */
INT wifi_hal_send_mgmt_frame_response(int ap_index, int type, int status, int status_code, uint8_t *frame, uint8_t *mac, int len, int rssi)
{
    if (status == MGMT_FRAME_RESPONSE_STATUS_OK) {
        wifi_send_wpa_supplicant_event(ap_index, frame, len);
    } else if (status == MGMT_FRAME_RESPONSE_STATUS_DENY) {
        wifi_send_response_failure(ap_index, mac, type, status_code, rssi);
    } else {
        wifi_hal_error_print("%s:%d: Undefined status\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
}

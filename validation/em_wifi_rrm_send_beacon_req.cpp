/*
 * HANDLER: wifi_rrm_send_beacon_req (platform/wifi-emulator)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/wifi-emulator/platform_emulator.c:595-603 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: none of its 22
 * arguments is read, nothing is logged and it returns 0 for every input.  The real implementation (src/wifi_hal_wnm_rrm.c:634) returns the dialog token
 * (> 0), 0 or -1 on error; its caller (src/wifi_hal.c:4068) only treats a negative result as failure, so 0 does not break the caller.  There is no fix switch.
 *
 * DESIGN NOTE (not counted, emulator stub): the beacon request is silently dropped and reported as accepted (dialog token 0).  Renamed
 * hwr_em_wifi_rrm_send_beacon_req because the real implementation has the same name.
 */
#include "hwr_esb.h"

#define wifi_rrm_send_beacon_req hwr_em_wifi_rrm_send_beacon_req

/* --- platform_emulator.c:595-603 --- */
extern "C" {
int wifi_rrm_send_beacon_req(struct wifi_interface_info_t *interface, const u8 *addr,
    u16 num_of_repetitions, u8 measurement_request_mode, u8 oper_class, u8 channel,
    u16 random_interval, u16 measurement_duration, u8 mode, const u8 *bssid,
    struct wpa_ssid_value *ssid, u8 *rep_cond, u8 *rep_cond_threshold, u8 *rep_detail,
    const u8 *ap_ch_rep, unsigned int ap_ch_rep_len, const u8 *req_elem, unsigned int req_elem_len,
    u8 *ch_width, u8 *ch_center_freq0, u8 *ch_center_freq1, u8 last_indication)
{
    return 0;
}
}

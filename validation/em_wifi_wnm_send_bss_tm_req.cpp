/*
 * HANDLER: wifi_wnm_send_bss_tm_req (platform/wifi-emulator)
 *
 * Function copied VERBATIM from rdk-wifi-hal: platform/wifi-emulator/platform_emulator.c:606-611 (~/Desktop/G/rdk-wifi-hal).  It is an empty stub: none of its 12
 * arguments is read, nothing is logged and it returns 0 for every input.  The real implementation (src/wifi_hal_wnm_rrm.c:1082) returns the dialog token
 * (> 0) or a negative value on error; its caller (src/wifi_hal.c:3874) only copies a positive token back, so 0 does not break the caller.  No fix switch.
 *
 * DESIGN NOTE (not counted, emulator stub): the BSS transition request is silently dropped and reported as sent (token 0).  Renamed
 * hwr_em_wifi_wnm_send_bss_tm_req because the real implementation has the same name.
 */
#include "hwr_ewb.h"

#define wifi_wnm_send_bss_tm_req hwr_em_wifi_wnm_send_bss_tm_req

/* --- platform_emulator.c:606-611 --- */
extern "C" {
int wifi_wnm_send_bss_tm_req(struct wifi_interface_info_t *interface, struct sta_info *sta,
    u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int, const u8 *bss_term_dur,
    const char *url, const u8 *nei_rep, size_t nei_rep_len, const u8 *mbo_attrs, size_t mbo_len)
{
    return 0;
}
}
